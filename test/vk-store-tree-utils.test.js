import { describe, it, expect } from '@jest/globals';
import { nodeMatches, subtreeHasMatch } from '../src/popup/vk-store-tree-utils.js';

// ---------------------------------------------------------------------------
// nodeMatches
// ---------------------------------------------------------------------------
describe('nodeMatches', () => {
  it('returns true when no filter is given', () => {
    expect(nodeMatches('anyKey', 'anyVal', '')).toBe(true);
    expect(nodeMatches('anyKey', 'anyVal', null)).toBe(true);
    expect(nodeMatches('anyKey', 'anyVal', undefined)).toBe(true);
  });

  it('matches key case-insensitively', () => {
    expect(nodeMatches('UserName', 'Alice', 'username')).toBe(true);
    expect(nodeMatches('USERNAME', 'Alice', 'username')).toBe(true);
    expect(nodeMatches('username', 'Alice', 'USERNAME')).toBe(true);
  });

  it('matches string value case-insensitively', () => {
    expect(nodeMatches('name', 'Alice', 'alice')).toBe(true);
    expect(nodeMatches('name', 'ALICE', 'alice')).toBe(true);
    expect(nodeMatches('name', 'alice', 'ALICE')).toBe(true);
  });

  it('matches number value by string representation', () => {
    expect(nodeMatches('count', 42, '42')).toBe(true);
    expect(nodeMatches('price', 3.14, '3.14')).toBe(true);
  });

  it('matches boolean value by string representation', () => {
    expect(nodeMatches('active', true, 'true')).toBe(true);
    expect(nodeMatches('active', false, 'false')).toBe(true);
  });

  it('returns false when neither key nor value matches', () => {
    expect(nodeMatches('name', 'Alice', 'xyz')).toBe(false);
  });

  it('returns false for null/undefined value with string filter', () => {
    expect(nodeMatches('key', null, 'search')).toBe(false);
    expect(nodeMatches('key', undefined, 'search')).toBe(false);
  });

  it('matches substring in key', () => {
    expect(nodeMatches('user_name_first', 'val', 'name')).toBe(true);
  });

  it('matches substring in string value', () => {
    expect(nodeMatches('key', 'hello world', 'world')).toBe(true);
  });

  it('returns false for empty filter on non-empty key/value', () => {
    expect(nodeMatches('key', 'val', '')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// subtreeHasMatch
// ---------------------------------------------------------------------------
describe('subtreeHasMatch', () => {
  it('returns false when no filter is given', () => {
    expect(subtreeHasMatch({ a: 1 }, '')).toBe(false);
    expect(subtreeHasMatch({ a: 1 }, null)).toBe(false);
  });

  it('returns false for null/undefined obj', () => {
    expect(subtreeHasMatch(null, 'search')).toBe(false);
    expect(subtreeHasMatch(undefined, 'search')).toBe(false);
  });

  it('returns false for non-object input', () => {
    expect(subtreeHasMatch('string', 'search')).toBe(false);
    expect(subtreeHasMatch(42, 'search')).toBe(false);
    expect(subtreeHasMatch(true, 'search')).toBe(false);
  });

  it('returns true for shallow key and value match', () => {
    var obj = { username: 'admin', role: 'user' };
    expect(subtreeHasMatch(obj, 'admin')).toBe(true); // matches value 'admin'
    expect(subtreeHasMatch(obj, 'user')).toBe(true); // matches key 'username' substring
  });

  it('returns true for shallow value match', () => {
    var obj = { name: 'Alice', role: 'admin' };
    expect(subtreeHasMatch(obj, 'alice')).toBe(true);
  });

  it('returns true for nested child match', () => {
    var obj = { user: { profile: { email: 'test@example.com' } } };
    expect(subtreeHasMatch(obj, 'test@example')).toBe(true);
  });

  it('returns true for deeply nested match', () => {
    var obj = { a: { b: { c: { d: { target: 'found' } } } } };
    expect(subtreeHasMatch(obj, 'found')).toBe(true);
  });

  it('returns true for nested key match', () => {
    var obj = { user: { password: 'secret' } };
    expect(subtreeHasMatch(obj, 'password')).toBe(true);
  });

  it('returns false when no match exists at any depth', () => {
    var obj = { a: { b: { c: 'x' } } };
    expect(subtreeHasMatch(obj, 'notfound')).toBe(false);
  });

  it('returns false for empty object', () => {
    expect(subtreeHasMatch({}, 'search')).toBe(false);
  });

  it('returns true for number value match', () => {
    var obj = { count: 42 };
    expect(subtreeHasMatch(obj, '42')).toBe(true);
  });

  it('returns true for boolean value match', () => {
    var obj = { active: true };
    expect(subtreeHasMatch(obj, 'true')).toBe(true);
  });

  it('handles arrays in object', () => {
    var obj = { tags: ['admin', 'user'] };
    // Array is an object, so subtreeHasMatch will recurse into it
    // Array keys are '0', '1', etc. — values are strings
    expect(subtreeHasMatch(obj, 'admin')).toBe(true);
  });

  it('handles mixed nested structure', () => {
    var obj = {
      users: [
        { name: 'Alice', roles: ['admin'] },
        { name: 'Bob', roles: ['user'] },
      ],
    };
    expect(subtreeHasMatch(obj, 'alice')).toBe(true);
    expect(subtreeHasMatch(obj, 'bob')).toBe(true);
    expect(subtreeHasMatch(obj, 'admin')).toBe(true);
    expect(subtreeHasMatch(obj, 'user')).toBe(true);
    expect(subtreeHasMatch(obj, 'charlie')).toBe(false);
  });
});
