// tests/ai-benchmarks/hallucinated-apis/new-apis.ts
import { expect } from 'vitest';
import { z } from 'zod';
import { db } from './drizzle';
import prisma from './prisma';

export async function checkPrisma() {
    // VULNERABLE
    await prisma.user.findAllWhere({ active: true });
    await prisma.post.findManyWhere({ published: true });
}

export function checkZod(data: any) {
    // VULNERABLE
    const result = z.string().validate(data);
    z.number().check(data);
    z.boolean().assert(data);
}

export async function checkNextjs(params: any, searchParams: any) {
    // VULNERABLE
    const id = params.get('id');
    const q = params.query;
    
    // VULNERABLE
    const page = searchParams.getAll('page');
    const sq = searchParams.query;
}

export async function checkDrizzle() {
    // VULNERABLE
    const users = await db.findMany('users');
    const one = await db.findOne('users', 1);
}

export function checkVitest() {
    const mock = () => {};
    // VULNERABLE
    expect(mock).toHaveBeenCalledOnce();
    expect({}).toStrictDeepEqual({});
    expect("a").toMatchSnapshot.inline();
}

export async function checkFetch() {
    // VULNERABLE
    await fetch.get('/api/data');
    await fetch.post('/api/save', { body: 'a' });
    fetch.create();
}

export async function checkMongoose(Model: any) {
    // VULNERABLE
    await Model.findAllById([1, 2]);
    await Model.updateById(1, {});
    await Model.deleteById(1);
    await Model.patch(1, {});
}
