-- ADR-0096 : les droits du presse-papiers d'une session RDP, évalués par l'Authorization Service à
-- sa création (les rôles du demandeur n'y sont plus à la connexion), et transmis au proxy à la
-- connexion. Faux pour toute session d'avant : refusés par défaut.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS clipboard_to_target BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS clipboard_from_target BOOLEAN NOT NULL DEFAULT false;
