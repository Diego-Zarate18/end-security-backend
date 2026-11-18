-- DEC-64: finalidades secundarias del aviso de privacidad (novedades y encuestas), apagadas por defecto
ALTER TABLE "users" ADD COLUMN "marketing_opt_in" BOOLEAN NOT NULL DEFAULT false;
