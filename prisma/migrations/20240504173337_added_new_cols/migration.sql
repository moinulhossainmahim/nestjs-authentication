/*
  Warnings:

  - Added the required column `fullName` to the `users` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "users" ADD COLUMN     "fullName" TEXT NOT NULL,
ADD COLUMN     "picture" TEXT;
