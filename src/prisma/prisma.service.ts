import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor() {
    super({
      datasources: {
        db: {
          url: 'postgresql://postgres:123@localhost:5432/nestjs?schema=public',
        },
      },
    });
  }
  onModuleInit() {
    this.$connect;
  }
  onModuleDestroy() {
    this.$disconnect();
  }
}
