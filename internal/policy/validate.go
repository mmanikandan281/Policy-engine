package policy

import (
	"errors"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
)

func ValidateCEL(expr string) error {
	if expr == "" {
		return errors.New("expr must not be empty")
	}
	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewConst("subject", decls.NewMapType(decls.String, decls.Dyn), nil),
			decls.NewConst("resource", decls.String, nil),
			decls.NewConst("action", decls.String, nil),
			decls.NewConst("metadata", decls.NewMapType(decls.String, decls.Dyn), nil),
			decls.NewConst("protocol", decls.String, nil),
			decls.NewConst("platform", decls.String, nil),
			decls.NewConst("cloud", decls.String, nil),
			decls.NewVar("request", decls.NewMapType(decls.String, decls.Dyn)), // ✅ added

		),
	)
	if err != nil {
		return err
	}
	ast, iss := env.Parse(expr)
	if iss != nil && iss.Err() != nil {
		return iss.Err()
	}
	checked, iss := env.Check(ast)
	if iss != nil && iss.Err() != nil {
		return iss.Err()
	}
	_, err = env.Program(checked)
	return err
}
