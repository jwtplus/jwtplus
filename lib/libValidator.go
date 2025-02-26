package lib

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

var customValidateAlphaWithSpace validator.Func = func(fl validator.FieldLevel) bool {
	a := fl.Field().String()

	regex, _ := regexp.Compile(string("^[a-zA-Z0-9@._\\-\\s]+$"))
	return regex.MatchString(a)
}

func RegisterCustomValidators() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("alphawithspace", customValidateAlphaWithSpace)

		//Return the json tag name instead of Golang variable name
		v.RegisterTagNameFunc(func(fld reflect.StructField) string {
			name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]

			if name == "-" {
				return ""
			}

			return name
		})
	}
}

type ErrorMsg struct {
	Field   string `json:"error_field"`
	Message string `json:"error_message"`
}

func getErrorMsg(fe validator.FieldError) ErrorMsg {
	switch fe.Tag() {
	case "required":
		return ErrorMsg{
			Message: "This field is required.",
		}
	case "alpha":
		return ErrorMsg{
			Message: "This field accepts alpha characters only.",
		}
	case "alphawithspace":
		return ErrorMsg{
			Message: "This field accepts alpha, numbers & spaces only.",
		}
	case "number":
		return ErrorMsg{
			Message: "This field accepts the numbers only.",
		}
	case "oneof":
		return ErrorMsg{
			Message: "This field accepts preconfigured values only.",
		}
	case "ulid":
		return ErrorMsg{
			Message: "This field requires a valid ULID.",
		}
	case "min":
		return ErrorMsg{
			Message: fmt.Sprintf("This field accepts the minimum value of %s", fe.Param()),
		}
	case "max":
		return ErrorMsg{
			Message: fmt.Sprintf("This field accepts the maximum value of %s", fe.Param()),
		}
	case "ip":
		return ErrorMsg{
			Message: "This field requires a valid ipv4 or ipv6 address.",
		}
	case "jwt":
		return ErrorMsg{
			Message: "This field requires a valid jwt token.",
		}
	}

	return ErrorMsg{
		Message: "Unknown error"}
}

func RestErrors(err error) []ErrorMsg {
	var ve validator.ValidationErrors

	if errors.As(err, &ve) {
		out := make([]ErrorMsg, len(ve))
		for i, fe := range ve {
			out[i] = getErrorMsg(fe)
			out[i].Field = fe.Field()
		}
		return out
	}

	return []ErrorMsg{}
}

func PayloadParsingError(err error) ErrorMsg {
	if reflect.TypeOf(err).Elem().String() == "json.SyntaxError" {
		return ErrorMsg{Message: "invalid json format"}
	}

	if reflect.TypeOf(err).Elem().String() == "json.UnmarshalTypeError" {
		return ErrorMsg{Message: "invalid json data type"}
	}

	return ErrorMsg{}
}
