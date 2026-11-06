import test from 'node:test';
import assert from 'node:assert/strict';
import {renderConsole} from '../ui.mjs';
test('管理画面はインラインstyle属性を含まず、<style> は nonce 付きだけ（CSP style-src は nonce のみ）',()=>{
 const html=renderConsole({nonce:'abc123'});
 assert.doesNotMatch(html,/\sstyle="/);
 assert.doesNotMatch(html,/<style(?![^>]*\snonce="abc123")/);
 assert.match(html,/<style nonce="abc123">/);
 assert.match(html,/\.brand-sub\{/);
});
