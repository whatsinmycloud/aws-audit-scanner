import { describe, it, expect } from 'vitest';
import { analysePublicPolicy } from './s3-policy.js';

const policy = (statement: unknown) =>
  JSON.stringify({ Version: '2012-10-17', Statement: statement });

describe('analysePublicPolicy', () => {
  it('detects the public-read-only case (deliberate static assets)', () => {
    const result = analysePublicPolicy(
      policy({
        Sid: 'PublicReadGetObject',
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::example/*',
      })
    );

    expect(result).toEqual({ read: true, write: false, list: false, conditionalStatements: 0 });
  });

  // The real shape found on a live account, 2026-07-28 — reported at the time
  // as merely "readable by anyone", which badly understated it.
  it('detects anonymous write, the case that motivated this check', () => {
    const result = analysePublicPolicy(
      policy({
        Effect: 'Allow',
        Principal: '*',
        Action: ['s3:GetObject', 's3:PutObject'],
        Resource: 'arn:aws:s3:::example/*',
      })
    );

    expect(result.write).toBe(true);
    expect(result.read).toBe(true);
  });

  it('detects public listing, which turns public files into a browsable index', () => {
    const result = analysePublicPolicy(
      policy({
        Effect: 'Allow',
        Principal: { AWS: '*' },
        Action: ['s3:GetObject', 's3:ListBucket'],
        Resource: 'arn:aws:s3:::example',
      })
    );

    expect(result.list).toBe(true);
    expect(result.write).toBe(false);
  });

  it.each([
    ['s3:*', { read: true, write: true, list: true }],
    ['*', { read: true, write: true, list: true }],
    ['s3:Put*', { read: false, write: true, list: false }],
    ['s3:Get*', { read: true, write: false, list: false }],
  ])('expands the wildcard action %s', (action, expected) => {
    const result = analysePublicPolicy(
      policy({ Effect: 'Allow', Principal: '*', Action: action, Resource: '*' })
    );

    expect({ read: result.read, write: result.write, list: result.list }).toEqual(expected);
  });

  it('ignores statements naming a specific principal', () => {
    const result = analysePublicPolicy(
      policy({
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::123456789012:root' },
        Action: 's3:PutObject',
        Resource: '*',
      })
    );

    expect(result.write).toBe(false);
  });

  it('ignores Deny statements', () => {
    const result = analysePublicPolicy(
      policy({ Effect: 'Deny', Principal: '*', Action: 's3:PutObject', Resource: '*' })
    );

    expect(result.write).toBe(false);
  });

  it('counts conditional public statements separately instead of crying wolf', () => {
    const result = analysePublicPolicy(
      policy({
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: '*',
        Condition: { IpAddress: { 'aws:SourceIp': '203.0.113.0/24' } },
      })
    );

    expect(result.read).toBe(false);
    expect(result.conditionalStatements).toBe(1);
  });

  it('handles a mix of statements', () => {
    const result = analysePublicPolicy(
      policy([
        { Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: '*' },
        { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:root' }, Action: 's3:*', Resource: '*' },
      ])
    );

    expect(result).toEqual({ read: true, write: false, list: false, conditionalStatements: 0 });
  });

  it('returns nothing public for malformed or empty documents', () => {
    for (const doc of ['not json', '{}', '{"Statement":[]}']) {
      expect(analysePublicPolicy(doc)).toEqual({
        read: false,
        write: false,
        list: false,
        conditionalStatements: 0,
      });
    }
  });
});
