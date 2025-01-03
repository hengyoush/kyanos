package rocketmq

import (
	"errors"
	"fmt"
)

type LanguageCode byte

const (
	JAVA    LanguageCode = iota // 0
	CPP                         // 1
	DOTNET                      // 2
	PYTHON                      // 3
	DELPHI                      // 4
	ERLANG                      // 5
	RUBY                        // 6
	OTHER                       // 7
	HTTP                        // 8
	GO                          // 9
	PHP                         // 10
	OMS                         // 11
	RUST                        // 12
	NODE_JS                     // 13
	UNKNOWN
)

// convertToLanguageCode converts a string to a LanguageCode.
func convertToLanguageCode(language string) (LanguageCode, error) {
	switch language {
	case "JAVA":
		return JAVA, nil
	case "CPP":
		return CPP, nil
	case "DOTNET":
		return DOTNET, nil
	case "PYTHON":
		return PYTHON, nil
	case "DELPHI":
		return DELPHI, nil
	case "ERLANG":
		return ERLANG, nil
	case "RUBY":
		return RUBY, nil
	case "OTHER":
		return OTHER, nil
	case "HTTP":
		return HTTP, nil
	case "GO":
		return GO, nil
	case "PHP":
		return PHP, nil
	case "OMS":
		return OMS, nil
	case "RUST":
		return RUST, nil
	case "NODE_JS":
		return NODE_JS, nil
	default:
		return 13, errors.New("unknown language: " + language)
	}
}

// convertToLanguageCodeFromByte converts a byte to a LanguageCode.
func convertToLanguageCodeFromByte(flag byte) (LanguageCode, error) {
	if flag > 13 {
		return 0, errors.New("unknown language flag: " + fmt.Sprint(flag))
	}
	return LanguageCode(flag), nil
}

func (lc LanguageCode) String() string {
	switch lc {
	case JAVA:
		return "JAVA"
	case CPP:
		return "CPP"
	case DOTNET:
		return "DOTNET"
	case PYTHON:
		return "PYTHON"
	case DELPHI:
		return "DELPHI"
	case ERLANG:
		return "ERLANG"
	case RUBY:
		return "RUBY"
	case OTHER:
		return "OTHER"
	case HTTP:
		return "HTTP"
	case GO:
		return "GO"
	case PHP:
		return "PHP"
	case OMS:
		return "OMS"
	case RUST:
		return "RUST"
	case NODE_JS:
		return "NODE_JS"
	default:
		return "UNKNOWN"
	}
}
