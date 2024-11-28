use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use petgraph::graph::{DiGraph, NodeIndex};
use regex::Regex;
use semver::{Version, VersionReq};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use which;
use std::process::Stdio;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to Python project
    #[arg(short, long)]
    path: String,

    /// Output format (text/dot/png)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Check for security vulnerabilities
    #[arg(short, long)]
    security: bool,

    /// Output file for graph
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Debug)]
struct Dependency {
    name: String,
    version_spec: String,
    version_req: Option<VersionReq>,
    resolved_version: Option<Version>,
    source_file: String,
}

struct DependencyAnalyzer {
    dependencies: HashMap<String, Vec<Dependency>>,
    graph: DiGraph<String, ()>,
    node_map: HashMap<String, NodeIndex>,
    known_conflicts: HashMap<String, HashSet<String>>,
}

impl DependencyAnalyzer {
    fn new() -> Self {
        let mut known_conflicts = HashMap::new();

        // Known conflicting package combinations
        known_conflicts.insert("tensorflow".to_string(), {
            let mut s = HashSet::new();
            s.insert("torch".to_string()); // Any torch version conflicts
            s.insert("jax".to_string());   // Potential memory conflicts
            s
        });

        known_conflicts.insert("torch".to_string(), {
            let mut s = HashSet::new();
            s.insert("tensorflow".to_string());
            s.insert("jax".to_string());
            s
        });

        known_conflicts.insert("numpy".to_string(), {
            let mut s = HashSet::new();
            s.insert("pandas<1.0.0".to_string()); // Old pandas versions
            s
        });

        Self {
            dependencies: HashMap::new(),
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            known_conflicts,
        }
    }

    fn scan_project(&mut self, path: &Path) -> Result<()> {
        println!("{}", "Scanning project for dependency files...".cyan());

        for entry in WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let file_name = entry.file_name().to_string_lossy();
            match file_name.as_ref() {
                "requirements.txt" => self.parse_requirements(&entry.path())?,
                "setup.py" => self.parse_setup_py(&entry.path())?,
                "Pipfile" => self.parse_pipfile(&entry.path())?,
                "pyproject.toml" => self.parse_pyproject_toml(&entry.path())?,
                "environment.yml" => self.parse_conda_yml(&entry.path())?,
                _ => continue,
            }
        }
        Ok(())
    }

    fn parse_version_spec(&self, spec: &str) -> Option<VersionReq> {
        // Convert pip-style version specs to semver-style
        let spec = spec
            .replace(">=", ">=")
            .replace("<=", "<=")
            .replace("==", "=")
            .replace("~=", "~");
        VersionReq::parse(&spec).ok()
    }

    fn parse_requirements(&mut self, path: &Path) -> Result<()> {
        println!("Parsing requirements.txt: {}", path.display());
        let content = fs::read_to_string(path)?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(pkg_name) = line.split(&['=', '>', '<', '~', '!'][..]).next() {
                let dep = Dependency {
                    name: pkg_name.trim().to_string(),
                    version_spec: line.to_string(),
                    version_req: self.parse_version_spec(line),
                    resolved_version: None,
                    source_file: path.display().to_string(),
                };
                self.add_dependency(dep);
            }
        }
        Ok(())
    }

    fn parse_setup_py(&mut self, path: &Path) -> Result<()> {
        println!("Parsing setup.py: {}", path.display());
        let content = fs::read_to_string(path)?;
        let install_requires_re = Regex::new(r"(?s)install_requires\s*=\s*\[(.*?)\]")?;

        if let Some(caps) = install_requires_re.captures(&content) {
            if let Some(requires) = caps.get(1) {
                for req in requires.as_str().split(',') {
                    let req = req.trim().trim_matches('\'').trim_matches('"');
                    if !req.is_empty() {
                        let dep = Dependency {
                            name: req
                                .split(&['=', '>', '<', '~', '!'][..])
                                .next()
                                .unwrap_or(req)
                                .trim()
                                .to_string(),
                            version_spec: req.to_string(),
                            version_req: self.parse_version_spec(req),
                            resolved_version: None,
                            source_file: path.display().to_string(),
                        };
                        self.add_dependency(dep);
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_pipfile(&mut self, path: &Path) -> Result<()> {
        println!("Parsing Pipfile: {}", path.display());
        let content = fs::read_to_string(path)?;
        let pipfile: toml::Value = toml::from_str(&content)?;

        if let Some(packages) = pipfile.get("packages").and_then(|p| p.as_table()) {
            for (name, version) in packages {
                let version_spec = match version {
                    toml::Value::String(v) => v.clone(),
                    _ => "*".to_string(),
                };
                let dep = Dependency {
                    name: name.clone(),
                    version_spec: version_spec.clone(),
                    version_req: self.parse_version_spec(&version_spec),
                    resolved_version: None,
                    source_file: path.display().to_string(),
                };
                self.add_dependency(dep);
            }
        }
        Ok(())
    }

    fn parse_pyproject_toml(&mut self, path: &Path) -> Result<()> {
        println!("Parsing pyproject.toml: {}", path.display());
        let content = fs::read_to_string(path)?;
        let pyproject: toml::Value = toml::from_str(&content)?;

        if let Some(project) = pyproject.get("project") {
            if let Some(dependencies) = project.get("dependencies").and_then(|d| d.as_array()) {
                for dep in dependencies {
                    if let Some(dep_str) = dep.as_str() {
                        if let Some(pkg_name) = dep_str.split(&['=', '>', '<', '~', '!'][..]).next()
                        {
                            let dep = Dependency {
                                name: pkg_name.trim().to_string(),
                                version_spec: dep_str.to_string(),
                                version_req: self.parse_version_spec(dep_str),
                                resolved_version: None,
                                source_file: path.display().to_string(),
                            };
                            self.add_dependency(dep);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_conda_yml(&mut self, path: &Path) -> Result<()> {
        println!("Parsing environment.yml: {}", path.display());
        let content = fs::read_to_string(path)?;
        if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
            if let Some(dependencies) = yaml
                .get("dependencies")
                .and_then(|d| d.as_sequence())
            {
                for dep in dependencies {
                    if let Some(dep_str) = dep.as_str() {
                        if let Some(pkg_name) = dep_str.split(&['=', '>', '<', '~', '!'][..]).next()
                        {
                            let dep = Dependency {
                                name: pkg_name.trim().to_string(),
                                version_spec: dep_str.to_string(),
                                version_req: self.parse_version_spec(dep_str),
                                resolved_version: None,
                                source_file: path.display().to_string(),
                            };
                            self.add_dependency(dep);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn add_dependency(&mut self, dep: Dependency) {
        let name = dep.name.clone();
        self.dependencies
            .entry(name.clone())
            .or_insert_with(Vec::new)
            .push(dep);

        if !self.node_map.contains_key(&name) {
            let node_idx = self.graph.add_node(name.clone());
            self.node_map.insert(name.clone(), node_idx);

            // Add known dependencies
            match name.as_str() {
                "pandas" => {
                    if let Some(&numpy_idx) = self.node_map.get("numpy") {
                        self.graph.add_edge(self.node_map[&name], numpy_idx, ());
                    }
                }
                "scikit-learn" => {
                    if let Some(&numpy_idx) = self.node_map.get("numpy") {
                        self.graph.add_edge(self.node_map[&name], numpy_idx, ());
                    }
                }
                "tensorflow" => {
                    if let Some(&numpy_idx) = self.node_map.get("numpy") {
                        self.graph.add_edge(self.node_map[&name], numpy_idx, ());
                    }
                }
                "transformers" => {
                    if let Some(&torch_idx) = self.node_map.get("torch") {
                        self.graph.add_edge(self.node_map[&name], torch_idx, ());
                    }
                    if let Some(&tensorflow_idx) = self.node_map.get("tensorflow") {
                        self.graph.add_edge(self.node_map[&name], tensorflow_idx, ());
                    }
                }
                _ => {}
            }
        }
    }

    fn check_conflicts(&self) -> Vec<String> {
        let mut conflicts = Vec::new();

        // Check for multiple version requirements
        for (name, deps) in &self.dependencies {
            if deps.len() > 1 {
                let versions: Vec<_> = deps
                    .iter()
                    .map(|d| format!("{} (in {})", d.version_spec, d.source_file))
                    .collect();

                // Find the highest required version
                let highest_version = deps
                    .iter()
                    .filter_map(|d| {
                        d.version_spec
                            .split(&['=', '>', '<', '~', '!'][..])
                            .nth(1)
                            .and_then(|v| Version::parse(v.trim()).ok())
                    })
                    .max();

                let suggestion = if let Some(version) = highest_version {
                    format!(
                        "\n      Suggestion: Use version >={} to satisfy all requirements",
                        version
                    )
                } else {
                    String::new()
                };

                conflicts.push(format!(
                    "Multiple version requirements for {}: {}{}",
                    name,
                    versions.join(", "),
                    suggestion
                ));
            }
        }

        // Check known conflicts
        for (pkg, conflict_pkgs) in &self.known_conflicts {
            if let Some(deps) = self.dependencies.get(pkg) {
                for conflict_pkg in conflict_pkgs {
                    let conflict_pkg_name = conflict_pkg
                        .split('<')
                        .next()
                        .unwrap_or(conflict_pkg);
                    if let Some(conflict_deps) = self.dependencies.get(conflict_pkg_name) {
                        conflicts.push(format!(
                            "Known conflict: {} {} may conflict with {} {}.\n      Suggestion: Consider using only one of these packages, or ensure they are compatible versions",
                            pkg,
                            deps[0].version_spec,
                            conflict_pkg,
                            conflict_deps[0].version_spec
                        ));
                    }
                }
            }
        }

        // Check version compatibility
        for (name, deps) in &self.dependencies {
            if let Some(dep) = deps.first() {
                if let Some(version_req) = &dep.version_req {
                    match name.as_str() {
                        "numpy" => {
                            if version_req.to_string().contains("<1.19") {
                                conflicts.push(format!(
                                    "Warning: numpy {} might be too old for modern ML frameworks.\n      Suggestion: Use numpy>=1.19.2 for better compatibility",
                                    dep.version_spec
                                ));
                            }
                        }
                        "tensorflow" => {
                            if let Some(numpy_deps) = self.dependencies.get("numpy") {
                                if let Some(numpy_dep) = numpy_deps.first() {
                                    if numpy_dep.version_spec.contains("<1.19") {
                                        conflicts.push(format!(
                                            "Potential conflict: tensorflow {} requires numpy>=1.19.2.\n      Suggestion: Upgrade numpy to version >=1.19.2",
                                            dep.version_spec
                                        ));
                                    }
                                }
                            }
                        }
                        "transformers" => {
                            // Check if both tensorflow and torch are present
                            if self.dependencies.contains_key("tensorflow")
                                && self.dependencies.contains_key("torch")
                            {
                                conflicts.push(
                                    "Warning: transformers is being used with both tensorflow and torch.\n      Suggestion: Consider using only one backend for better efficiency"
                                        .to_string(),
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        conflicts
    }

    fn generate_graph(&self, format: &str) -> Result<String> {
        match format {
            "dot" | "png" => {
                let mut dot = String::from("digraph dependencies {\n");
                dot.push_str("    rankdir=LR;\n");
                dot.push_str("    compound=true;\n");
                dot.push_str("    node [shape=box, style=rounded, fontname=\"Arial\"];\n");
                dot.push_str("    edge [color=\"#666666\", fontname=\"Arial\"];\n\n");

                // Create subgraphs for package categories
                let mut ml_packages = Vec::new();
                let mut data_packages = Vec::new();
                let mut util_packages = Vec::new();
                let mut other_packages = Vec::new();

                // Categorize packages
                for node in self.graph.node_indices() {
                    let name = &self.graph[node];
                    match name.as_str() {
                        "tensorflow" | "torch" | "jax" | "transformers" | "scikit-learn" => {
                            ml_packages.push(node);
                        }
                        "numpy" | "pandas" | "matplotlib" | "seaborn" => {
                            data_packages.push(node);
                        }
                        "tqdm" | "pillow" | "tokenizers" => {
                            util_packages.push(node);
                        }
                        _ => {
                            other_packages.push(node);
                        }
                    }
                }

                // Helper function to generate node attributes
                let node_attrs = |name: &str, deps: &Vec<Dependency>| -> String {
                    let has_conflicts = deps.len() > 1;
                    let is_known_conflict = self.known_conflicts.contains_key(name);
                    
                    let (color, style) = if has_conflicts {
                        ("#CC0000", "bold") // Red for version conflicts
                    } else if is_known_conflict {
                        ("#FF6600", "bold") // Orange for known conflicts
                    } else {
                        ("#2D3436", "normal") // Dark gray for normal nodes
                    };

                    let label = if has_conflicts {
                        format!("{}\n({} versions)", name, deps.len())
                    } else {
                        name.to_string()
                    };

                    format!(
                        "color=\"{}\", fontcolor=\"{}\", style=\"rounded,filled\", fillcolor=\"white\", \
                         fontname=\"Arial\", fontsize=\"10\", margin=\"0.2\", height=\"0.4\", label=\"{}\"",
                        color, color, label.replace("\"", "\\\"")
                    )
                };

                // Generate subgraphs
                let subgraphs = [
                    ("cluster_ml", "Machine Learning", &ml_packages),
                    ("cluster_data", "Data Processing", &data_packages),
                    ("cluster_util", "Utilities", &util_packages),
                    ("cluster_other", "Other", &other_packages),
                ];

                for (cluster_name, label, packages) in subgraphs.iter() {
                    if !packages.is_empty() {
                        dot.push_str(&format!("    subgraph {} {{\n", cluster_name));
                        dot.push_str(&format!("        label=\"{}\";\n", label));
                        dot.push_str("        style=rounded;\n");
                        dot.push_str("        color=\"#E0E0E0\";\n");
                        dot.push_str("        bgcolor=\"#F8F8F8\";\n\n");

                        for &node in *packages {
                            let name = &self.graph[node];
                            let deps = &self.dependencies[name];
                            let node_id = format!("n{}", node.index());
                            dot.push_str(&format!(
                                "        {} [{}];\n",
                                node_id,
                                node_attrs(name, deps)
                            ));
                        }
                        dot.push_str("    }\n\n");
                    }
                }

                // Add edges with improved styling
                for edge in self.graph.edge_indices() {
                    let (from, to) = self.graph.edge_endpoints(edge).unwrap();
                    let from_name = &self.graph[from];
                    let to_name = &self.graph[to];
                    
                    let is_conflict = self.known_conflicts
                        .get(from_name)
                        .map(|conflicts| conflicts.contains(to_name))
                        .unwrap_or(false);

                    let style = if is_conflict {
                        "color=\"#CC0000\", style=\"dashed\", penwidth=2.0, arrowsize=1.5"
                    } else {
                        "color=\"#666666\", penwidth=1.0, arrowsize=1.0"
                    };

                    dot.push_str(&format!(
                        "    n{} -> n{} [{}];\n",
                        from.index(), to.index(), style
                    ));
                }

                dot.push_str("}\n");
                Ok(dot)
            }
            "text" => {
                let mut output = String::new();
                for (name, deps) in &self.dependencies {
                    for dep in deps {
                        output.push_str(&format!(
                            "{} ({}) [from {}]\n",
                            name, dep.version_spec, dep.source_file
                        ));
                    }
                }
                Ok(output)
            }
            _ => Err(anyhow::anyhow!("Unsupported output format")),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut analyzer = DependencyAnalyzer::new();

    // Scan project
    analyzer
        .scan_project(Path::new(&args.path))
        .context("Failed to scan project")?;

    // Check for conflicts
    let conflicts = analyzer.check_conflicts();
    if !conflicts.is_empty() {
        println!("\n{}", "Potential Conflicts Found:".red());
        for conflict in conflicts {
            println!("  - {}", conflict);
        }
    }

    // Generate and output dependency graph
    let graph_output = analyzer
        .generate_graph(&args.format)
        .context("Failed to generate graph")?;

    // Handle output based on format
    if let Some(output_file) = args.output {
        if args.format == "dot" || args.format == "png" {
            // Write the DOT content to a file
            let dot_file = if output_file.ends_with(".dot") {
                output_file.clone()
            } else {
                // If output_file ends with '.png', generate a temporary DOT file
                let dot_file = output_file.replace(".png", ".dot");
                dot_file
            };

            fs::write(&dot_file, &graph_output)
                .with_context(|| format!("Failed to write graph to {}", dot_file))?;
            println!("\n{}", format!("Graph written to {}", dot_file).green());

            // If format is PNG, generate PNG using 'dot' command
            if args.format == "png" || output_file.ends_with(".png") {
                let png_file = if output_file.ends_with(".png") {
                    output_file.clone()
                } else {
                    output_file.replace(".dot", ".png")
                };

                println!("{}", "Attempting to generate PNG...".cyan());

                // Check if 'dot' command is available
                if which::which("dot").is_err() {
                    println!(
                        "{}",
                        "Graphviz 'dot' command not found. Please install Graphviz to generate PNG files.".yellow()
                    );
                } else {
                    let output = std::process::Command::new("dot")
                        .args(["-Tpng", &dot_file, "-o", &png_file])
                        .stderr(Stdio::piped())
                        .output();

                    match output {
                        Ok(output) => {
                            if output.status.success() {
                                println!(
                                    "{}",
                                    format!("PNG graph generated: {}", png_file).green()
                                );
                            } else {
                                let err = String::from_utf8_lossy(&output.stderr);
                                println!(
                                    "{}",
                                    "Failed to generate PNG. Error from 'dot':".yellow()
                                );
                                println!("{}", err);
                            }
                        }
                        Err(e) => {
                            println!(
                                "{}",
                                format!("Failed to execute 'dot' command: {}", e).yellow()
                            );
                        }
                    }
                }
            }
        } else if args.format == "text" {
            fs::write(&output_file, &graph_output)
                .with_context(|| format!("Failed to write graph to {}", output_file))?;
            println!("\n{}", format!("Graph written to {}", output_file).green());
        } else {
            println!("{}", "Unsupported format specified.".red());
        }
    } else {
        // No output file specified
        if args.format == "text" {
            println!("\n{}", "Dependency Graph:".green());
            println!("{}", graph_output);
        } else {
            println!(
                "{}",
                "Please specify an output file when using 'dot' or 'png' format.".yellow()
            );
        }
    }

    // Security check (placeholder - can be enhanced with actual security DB integration)
    if args.security {
        println!("\n{}", "Security Check:".yellow());
        println!("Security checking is not implemented yet");
    }

    Ok(())
}
