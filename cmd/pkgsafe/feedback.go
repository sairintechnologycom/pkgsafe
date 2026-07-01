package main

import (
	"flag"
	"fmt"

	"github.com/niyam-ai/pkgsafe/internal/feedback"
)

func cmdFeedback(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pkgsafe feedback create --input <scan.json> [--output-dir .pkgsafe/feedback] [--reason <text>] [--command <command>]")
	}
	switch args[0] {
	case "create":
		return cmdFeedbackCreate(args[1:])
	default:
		return fmt.Errorf("unknown feedback subcommand %q", args[0])
	}
}

func cmdFeedbackCreate(args []string) error {
	fs := flag.NewFlagSet("feedback-create", flag.ContinueOnError)
	input := fs.String("input", "", "sanitized PkgSafe --json output file")
	outputDir := fs.String("output-dir", ".pkgsafe/feedback", "directory for generated feedback artifacts")
	reason := fs.String("reason", "", "why the package is believed to be safe")
	command := fs.String("command", "", "command or workflow that produced the finding")
	if err := fs.Parse(args); err != nil {
		return err
	}
	artifacts, err := feedback.Create(feedback.Options{
		InputPath: *input,
		OutputDir: *outputDir,
		Reason:    *reason,
		Command:   *command,
	})
	if err != nil {
		return err
	}
	fmt.Println("PkgSafe feedback generated")
	fmt.Printf("Fingerprint: %s\n", artifacts.Feedback.Fingerprint)
	fmt.Printf("JSON: %s\n", artifacts.JSONPath)
	fmt.Printf("Markdown: %s\n", artifacts.MarkdownPath)
	return nil
}
