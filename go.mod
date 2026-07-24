module github.com/hasandenizuk/credroute

go 1.26

require gopkg.in/yaml.v3 v3.0.1

// v0.1.0 shipped a machine-specific default vault directory in its help
// output and describe manifest. Superseded by v0.1.1.
retract v0.1.0
