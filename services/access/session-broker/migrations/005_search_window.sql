-- ADR-0080 : la recherche des sessions lit sa fenêtre sur created_at, les plus récentes d'abord.
CREATE INDEX IF NOT EXISTS sessions_created_idx ON sessions (created_at DESC, id DESC);
