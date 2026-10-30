-- ADR-0039 : la clé d'hôte de la cible de chaque compte, épinglée — une ligne
-- `ssh-ed25519 AAAA…` normalisée, publique. Vide : un compte d'avant l'épinglage,
-- dont aucune session ni rotation ne s'ouvre tant qu'elle n'est pas posée.
ALTER TABLE privileged_accounts ADD COLUMN IF NOT EXISTS host_key TEXT NOT NULL DEFAULT '';
