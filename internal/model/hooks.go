package model

import (
	"example.com/jit-engine/internal/policy"
	"gorm.io/gorm"
)

func (p *Policy) BeforeCreate(tx *gorm.DB) (err error) {
	return policy.ValidateCEL(p.Expr)
}

func (p *Policy) BeforeUpdate(tx *gorm.DB) (err error) {
	if tx.Statement.Changed("Expr") {
		return policy.ValidateCEL(p.Expr)
	}
	return nil
}
