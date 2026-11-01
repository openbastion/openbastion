-- ADR-0067 : une session vers un compte qui l'exige attend l'approbation d'une autre personne,
-- avec un ticket. Ce qui distingue une telle demande d'un break-glass, et la référence que
-- l'approbateur lit. Vide et faux pour toute session d'avant.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS approval_required BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ticket TEXT NOT NULL DEFAULT '';
