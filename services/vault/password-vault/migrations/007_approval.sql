-- ADR-0067 : un compte peut exiger qu'une session vers lui attende l'approbation d'une autre
-- personne, avec un ticket. Faux pour tout compte d'avant.
ALTER TABLE privileged_accounts ADD COLUMN IF NOT EXISTS approval_required BOOLEAN NOT NULL DEFAULT false;
