package main

import (
	"log"
	"os"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"example.com/jit-engine/internal/model"
)

func main() {
	godotenv.Load()
	dsn := os.Getenv("DATABASE_URL")

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	db.Exec("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
	db.Exec("CREATE EXTENSION IF NOT EXISTS pg_trgm;")

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{
		{
			ID: "20251008_create_policies",
			Migrate: func(tx *gorm.DB) error {
				if err := tx.AutoMigrate(&model.Policy{}, &model.PolicyAudit{}); err != nil {
					return err
				}
				if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_policies_actions ON policies USING gin (actions);`).Error; err != nil {
					return err
				}
				if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_policies_metadata ON policies USING gin (metadata);`).Error; err != nil {
					return err
				}
				if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_policies_resource_trgm ON policies USING gin (resource gin_trgm_ops);`).Error; err != nil {
					return err
				}
				if err := tx.Exec(`ALTER TABLE policies ADD CONSTRAINT effect_check CHECK (effect IN ('allow','deny'));`).Error; err != nil {
					// ignore if exists
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error { return tx.Migrator().DropTable("policy_audits", "policies") },
		},
		{
			ID: "20251009_add_provider_to_policies",
			Migrate: func(tx *gorm.DB) error {
				if err := tx.Exec(`ALTER TABLE policies ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'global';`).Error; err != nil {
					return err
				}
				if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_policies_provider ON policies (provider);`).Error; err != nil {
					return err
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				if err := tx.Exec(`DROP INDEX IF EXISTS idx_policies_provider;`).Error; err != nil {
					return err
				}
				return tx.Exec(`ALTER TABLE policies DROP COLUMN IF EXISTS provider;`).Error
			},
		},
	})

	if err := m.Migrate(); err != nil {
		log.Fatal(err)
	}
	log.Println("Migrations applied")
}

/*

psql -U postgres -d jitengine

\x on
SELECT id, name, effect, resource, actions, enabled, priority FROM policies;
\x off



*/
