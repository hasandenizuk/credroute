// allow-claude-code: new multi-file build for the "agent-native command
// layer" milestone (roadmap.md section 4): imperative commands that edit
// config.yaml so users and agents never hand-write YAML. Mechanical
// translation of that milestone's spec to Go using yaml.v3's Node API;
// low ambiguity, reviewed alongside the commands that call it.
//
// This file adds Document: config.yaml loaded as an editable YAML node
// tree rather than only a decoded Config struct, so identity/route
// editing commands can add or change one value without destroying
// comments and formatting elsewhere in a hand-annotated file (the spec's
// "preserve comments where reasonably possible"). Every mutation is
// in-memory only; callers decide when to Snapshot (re-decode + strict
// schema check, the same one `credroute config validate` runs) and only
// call Save if that snapshot validates, so a bad edit can never reach
// disk.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/hasandenizuk/credroute/internal/fsutil"
)

// Document is config.yaml loaded as an editable YAML node tree.
type Document struct {
	Path string
	root yaml.Node // Kind == yaml.DocumentNode
}

// OpenDocument reads the config at path (same resolution precedence as
// Load: path arg, else CREDROUTE_CONFIG, else the default path) as an
// editable node tree. The file must already exist and parse as a YAML
// mapping document; OpenDocument does not create one (that is
// `credroute init`'s job).
func OpenDocument(path string) (*Document, error) {
	resolved, err := resolvedPath(path)
	if err != nil {
		return nil, err
	}
	expanded, err := ExpandHome(resolved)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf("open config %s: %w", expanded, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", expanded, err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config %s: expected a YAML mapping document at the top level", expanded)
	}

	return &Document{Path: expanded, root: root}, nil
}

// Snapshot re-decodes the document's current in-memory state into a
// Config, with the exact same strict-schema decode Load uses
// (KnownFields, so a mutation that accidentally introduces an unknown
// field is caught here, not at the next `credroute resolve`). It does not
// mutate the document or touch disk. Callers run Validate on the result
// before deciding whether to Save.
func (d *Document) Snapshot() (*Config, error) {
	b, err := yaml.Marshal(&d.root)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse edited config: %w", err)
	}
	cfg.Path = d.Path
	return &cfg, nil
}

// Save writes the document's current in-memory state back to Path,
// atomically and at 0600 (matching the permissions `credroute init`
// writes a fresh config with). Callers must have already validated a
// Snapshot; Save itself does not validate.
func (d *Document) Save() error {
	b, err := yaml.Marshal(&d.root)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := fsutil.WriteFileAtomic(d.Path, b, 0o600); err != nil {
		return fmt.Errorf("save config %s: %w", d.Path, err)
	}
	return nil
}

// rootMapping returns the document's top-level mapping node.
func (d *Document) rootMapping() (*yaml.Node, error) {
	if d.root.Kind != yaml.DocumentNode || len(d.root.Content) == 0 || d.root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config: document root is not a YAML mapping")
	}
	return d.root.Content[0], nil
}

// findMapEntry returns the value node for key in mapping m, or nil if key
// is not present. m must be a MappingNode.
func findMapEntry(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// ensureMapEntry returns the value node for key in m, appending a fresh
// key + empty-container(kind) pair at the end of m's content if key is
// not already present.
func ensureMapEntry(m *yaml.Node, key string, kind yaml.Kind) *yaml.Node {
	if v := findMapEntry(m, key); v != nil {
		return v
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	tag := "!!map"
	if kind == yaml.SequenceNode {
		tag = "!!seq"
	}
	valNode := &yaml.Node{Kind: kind, Tag: tag}
	m.Content = append(m.Content, keyNode, valNode)
	return valNode
}

// setScalarEntry sets key's value to a plain string scalar in mapping m,
// adding the key if it is not already present, and reusing (mutating in
// place) the existing value node otherwise so any comment attached to it
// survives.
func setScalarEntry(m *yaml.Node, key, value string) {
	if v := findMapEntry(m, key); v != nil {
		v.Kind = yaml.ScalarNode
		v.Tag = "!!str"
		v.Value = value
		v.Content = nil
		return
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
	)
}

// removeMapEntry deletes key from mapping m, if present.
func removeMapEntry(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// replaceValue overwrites dst's kind/tag/value/content/style/anchor with
// src's, but deliberately leaves dst's own comment fields (HeadComment,
// LineComment, FootComment) untouched, so replacing e.g. a credential's
// value does not delete a comment the operator wrote next to it.
func replaceValue(dst, src *yaml.Node) {
	dst.Kind = src.Kind
	dst.Tag = src.Tag
	dst.Value = src.Value
	dst.Content = src.Content
	dst.Style = src.Style
	dst.Anchor = src.Anchor
}

// encodeNode returns a fresh yaml.Node tree for v, using yaml.v3's normal
// struct/map/slice encoding rules (so it stays in sync with the yaml tags
// on Config's own types automatically).
func encodeNode(v interface{}) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, fmt.Errorf("encode %T: %w", v, err)
	}
	return &n, nil
}

// AddIdentity adds a new identities.<id> entry with the given label and
// no platforms yet (platforms/credentials are added afterwards via
// UpsertCredential, from `identity edit --add-credential`). Returns an
// error if id already exists.
func (d *Document) AddIdentity(id, label string) error {
	m, err := d.rootMapping()
	if err != nil {
		return err
	}
	identities := ensureMapEntry(m, "identities", yaml.MappingNode)
	if findMapEntry(identities, id) != nil {
		return fmt.Errorf("identity %q already exists (use `identity edit`)", id)
	}
	node, err := encodeNode(Identity{Label: label})
	if err != nil {
		return err
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: id}
	identities.Content = append(identities.Content, keyNode, node)
	return nil
}

// SetIdentityLabel replaces identities.<id>.label. Returns an error if id
// does not exist.
func (d *Document) SetIdentityLabel(id, label string) error {
	identNode, err := d.findIdentity(id)
	if err != nil {
		return err
	}
	setScalarEntry(identNode, "label", label)
	return nil
}

// UpsertCredential adds or replaces
// identities.<id>.platforms.<platform>.credentials.<access>, creating the
// platforms/platform/credentials mappings if they do not exist yet.
// Returns an error if id does not exist (AddIdentity must run first).
func (d *Document) UpsertCredential(id, platform, access string, cred Credential) error {
	identNode, err := d.findIdentity(id)
	if err != nil {
		return err
	}
	platforms := ensureMapEntry(identNode, "platforms", yaml.MappingNode)
	platNode := ensureMapEntry(platforms, platform, yaml.MappingNode)
	creds := ensureMapEntry(platNode, "credentials", yaml.MappingNode)

	newVal, err := encodeNode(cred)
	if err != nil {
		return err
	}
	if existing := findMapEntry(creds, access); existing != nil {
		replaceValue(existing, newVal)
		return nil
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: access}
	creds.Content = append(creds.Content, keyNode, newVal)
	return nil
}

// findIdentity returns the mapping node for identities.<id>, or an error
// naming `identity add` as the fix if it does not exist.
func (d *Document) findIdentity(id string) (*yaml.Node, error) {
	m, err := d.rootMapping()
	if err != nil {
		return nil, err
	}
	identities := findMapEntry(m, "identities")
	if identities == nil {
		return nil, fmt.Errorf("no identities are defined yet (run `identity add %s` first)", id)
	}
	identNode := findMapEntry(identities, id)
	if identNode == nil {
		return nil, fmt.Errorf("identity %q not found (run `identity add %s` first)", id, id)
	}
	return identNode, nil
}

// AddRule appends rule to the rules[] list. index selects the insertion
// position (0-based); a negative index means the default: append at the
// end, unless the last existing rule is a catch-all (empty match block),
// in which case the new rule is inserted just before it, since a
// catch-all rule is only legal as the final rule (config.Validate
// enforces this) and a naive append would silently make the new rule
// unreachable.
func (d *Document) AddRule(rule Rule, index int) error {
	m, err := d.rootMapping()
	if err != nil {
		return err
	}
	rules := ensureMapEntry(m, "rules", yaml.SequenceNode)

	newNode, err := encodeNode(rule)
	if err != nil {
		return err
	}

	n := len(rules.Content)
	pos := index
	if pos < 0 {
		pos = n
		if n > 0 && ruleNodeIsCatchAll(rules.Content[n-1]) {
			pos = n - 1
		}
	}
	if pos > n {
		pos = n
	}
	if pos < 0 {
		pos = 0
	}

	rules.Content = append(rules.Content, nil)
	copy(rules.Content[pos+1:], rules.Content[pos:])
	rules.Content[pos] = newNode
	return nil
}

// ruleNodeIsCatchAll reports whether a rule's match{} block (as raw
// nodes) has no conditions at all, mirroring RuleMatch.IsEmpty on the
// decoded struct.
func ruleNodeIsCatchAll(ruleNode *yaml.Node) bool {
	matchNode := findMapEntry(ruleNode, "match")
	if matchNode == nil {
		return true
	}
	return len(matchNode.Content) == 0
}

// AssignRule edits rules[].use for the rule identified by ruleID:
// identity/access/verify are applied only when non-nil (so a command
// layer can pass "only change what was actually flagged"). Passing a
// non-nil verify pointing at an empty string removes the rule's verify
// override entirely (reverting to defaults.verify). Returns an error if
// ruleID is not found.
func (d *Document) AssignRule(ruleID string, identity, access, verify *string) error {
	m, err := d.rootMapping()
	if err != nil {
		return err
	}
	rules := findMapEntry(m, "rules")
	if rules == nil {
		return fmt.Errorf("no rules are defined yet")
	}
	for _, rn := range rules.Content {
		idNode := findMapEntry(rn, "id")
		if idNode == nil || idNode.Value != ruleID {
			continue
		}
		use := ensureMapEntry(rn, "use", yaml.MappingNode)
		if identity != nil {
			setScalarEntry(use, "identity", *identity)
		}
		if access != nil {
			setScalarEntry(use, "access", *access)
		}
		if verify != nil {
			if *verify == "" {
				removeMapEntry(use, "verify")
			} else {
				setScalarEntry(use, "verify", *verify)
			}
		}
		return nil
	}
	return fmt.Errorf("rule %q not found", ruleID)
}
