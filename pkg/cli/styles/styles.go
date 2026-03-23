package styles

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func init() {
	// Respect NO_COLOR standard (highest priority)
	if os.Getenv("NO_COLOR") != "" {
		lipgloss.SetColorProfile(termenv.Ascii)
		return
	}

	// Enable color output if FORCE_COLOR is set
	if os.Getenv("FORCE_COLOR") != "" || os.Getenv("FORCE_COLOR") == "1" {
		lipgloss.SetColorProfile(termenv.TrueColor)
		return
	}

	// Otherwise, use auto-detection (default Lipgloss behavior)
	// This will enable colors when outputting to a TTY
}

// Color palette - subtle and professional
var (
	// Base colors
	gray   = lipgloss.Color("240")
	dimmed = lipgloss.Color("245")

	// Semantic colors
	green  = lipgloss.Color("42")  // Success
	red    = lipgloss.Color("203") // Error
	yellow = lipgloss.Color("221") // Warning
	cyan   = lipgloss.Color("86")  // Info/highlight
	blue   = lipgloss.Color("75")  // Secondary info
)

// Styles for different message types
var (
	// Success message style - subtle green
	Success = lipgloss.NewStyle().
		Foreground(green).
		Bold(false)

	// Error message style - subtle red
	Error = lipgloss.NewStyle().
		Foreground(red).
		Bold(false)

	// Warning message style - subtle yellow
	Warning = lipgloss.NewStyle().
		Foreground(yellow).
		Bold(false)

	// Info message style - subtle cyan
	Info = lipgloss.NewStyle().
		Foreground(cyan).
		Bold(false)

	// Label style - dimmed for prefixes
	Label = lipgloss.NewStyle().
		Foreground(dimmed).
		Bold(false)

	// Value style - highlighted for important data
	Value = lipgloss.NewStyle().
		Foreground(cyan).
		Bold(true)

	// Code/Key style - for technical identifiers
	Code = lipgloss.NewStyle().
		Foreground(blue).
		Bold(false)

	// Subtle style - for less important text
	Subtle = lipgloss.NewStyle().
		Foreground(gray).
		Bold(false)
)

// Helper functions for common patterns
func Successf(format string, args ...interface{}) string {
	return Success.Render(fmt.Sprintf(format, args...))
}

func Errorf(format string, args ...interface{}) string {
	return Error.Render(fmt.Sprintf(format, args...))
}

func Infof(format string, args ...interface{}) string {
	return Info.Render(fmt.Sprintf(format, args...))
}

func Warningf(format string, args ...interface{}) string {
	return Warning.Render(fmt.Sprintf(format, args...))
}
