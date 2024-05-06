-- AlterTable
ALTER TABLE "users" ADD COLUMN     "isGoogleLogin" BOOLEAN NOT NULL DEFAULT false,
ALTER COLUMN "hash" DROP NOT NULL;
