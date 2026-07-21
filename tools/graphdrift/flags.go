package main

import "flag"

// flags holds the CLI surface. Defaults are relative to tools/graphdrift, so
// `go run -C tools/graphdrift .` works from a repo checkout with no arguments.
type flags struct {
	manifest string
	snapshot string
	metadata string
	format   string
	update   bool

	set *flag.FlagSet
}

func newFlagSet() *flags {
	f := &flags{set: flag.NewFlagSet("graphdrift", flag.ContinueOnError)}
	f.set.StringVar(&f.manifest, "manifest", "../../spec/graph-beta-surface.json", "path to the consumed-beta-surface manifest")
	f.set.StringVar(&f.snapshot, "snapshot", "../../spec/graph-beta-snapshot.json", "path to the committed beta-surface snapshot")
	f.set.StringVar(&f.metadata, "metadata", "", "read CSDL from this file instead of fetching the live $metadata")
	f.set.StringVar(&f.format, "format", "md", "output format: md|json")
	f.set.BoolVar(&f.update, "update", false, "rewrite the snapshot from the metadata source instead of diffing")
	return f
}

func (f *flags) parse(args []string) error {
	return f.set.Parse(args)
}
