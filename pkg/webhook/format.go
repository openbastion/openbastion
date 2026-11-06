package webhook

import (
	"encoding/json"
	"errors"
)

// Format is the shape a channel reads (ADR-0074). The destination has nothing to do with it: a
// receiver compatible with Slack takes the slack format, whatever its host.
type Format string

const (
	// FormatGeneric is the caller's own JSON message, the contract of the receivers in place.
	FormatGeneric Format = "generic"
	// FormatSlack is what an incoming webhook of Slack reads.
	FormatSlack Format = "slack"
	// FormatTeams is what a Workflows webhook of Teams reads: an Adaptive Card, without any action.
	// A message is never an authority: there is nothing to press.
	FormatTeams Format = "teams"
)

// ParseFormat reads a configuration value; empty is generic. Anything else is an error rather than
// a default: a typing mistake must not leave a channel that cannot read what it is sent.
func ParseFormat(value string) (Format, error) {
	switch value {
	case "", string(FormatGeneric):
		return FormatGeneric, nil
	case string(FormatSlack):
		return FormatSlack, nil
	case string(FormatTeams):
		return FormatTeams, nil
	}
	return "", errors.New("the format must be generic, slack or teams")
}

type adaptiveTextBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
	Wrap bool   `json:"wrap"`
}

type adaptiveCard struct {
	Type    string              `json:"type"`
	Version string              `json:"version"`
	Body    []adaptiveTextBlock `json:"body"`
}

type adaptiveAttachment struct {
	ContentType string       `json:"contentType"`
	Content     adaptiveCard `json:"content"`
}

type teamsMessage struct {
	Type        string               `json:"type"`
	Attachments []adaptiveAttachment `json:"attachments"`
}

// Body is what is sent in this format. generic is returned untouched for FormatGeneric. A chat
// format carries phrase alone, never the fields of generic: phrase is the one thing the caller
// builds from fixed words, numbers and SafeText, so nothing a person wrote reaches the channel as is.
func (f Format) Body(generic []byte, phrase string) ([]byte, error) {
	switch f {
	case FormatGeneric:
		return generic, nil
	case FormatSlack, FormatTeams:
		if phrase == "" {
			return nil, errors.New("a chat message needs a phrase")
		}
	default:
		return nil, errors.New("unknown format")
	}
	if f == FormatSlack {
		return json.Marshal(struct {
			Text string `json:"text"`
		}{phrase})
	}
	return json.Marshal(teamsMessage{Type: "message", Attachments: []adaptiveAttachment{{
		ContentType: "application/vnd.microsoft.card.adaptive",
		Content: adaptiveCard{Type: "AdaptiveCard", Version: "1.2", Body: []adaptiveTextBlock{
			{Type: "TextBlock", Text: phrase, Wrap: true},
		}},
	}}})
}
