import test from 'node:test';
import assert from 'node:assert/strict';
import {createActivityAcquisition,NEWS_SOURCE_IDS} from '../activitySources.mjs';

const FIXED = {
  yahoo_domestic:'https://news.yahoo.co.jp/rss/topics/domestic.xml',
  yahoo_entertainment:'https://news.yahoo.co.jp/rss/topics/entertainment.xml',
  yahoo_sports:'https://news.yahoo.co.jp/rss/topics/sports.xml',
  google_japan:'https://news.google.com/rss?hl=ja&gl=JP&ceid=JP:ja',
  google_entertainment:'https://news.google.com/rss/headlines/section/topic/ENTERTAINMENT?hl=ja&gl=JP&ceid=JP:ja',
  google_business:'https://news.google.com/rss/headlines/section/topic/BUSINESS?hl=ja&gl=JP&ceid=JP:ja',
};

test('RSS news sources are fixed, public and have no caller-defined query or key',()=>{
  for(const source of Object.keys(FIXED)) assert(NEWS_SOURCE_IDS.includes(source));
  const denied=['yahoo_private','google_search','shopping_paid','arbitrary_news'];
  for(const source of denied) assert(!NEWS_SOURCE_IDS.includes(source));
});

test('fixed RSS goes through bounded, read-only gateway and preserves bytes',async()=>{
  const calls=[];
  const rss='<?xml version="1.0" encoding="UTF-8"?><rss><channel><item><title>イベント</title><link>https://example.org/event</link></item></channel></rss>';
  const collector=createActivityAcquisition({
    fetchImpl:async(url,opts)=>{
      calls.push({url,opts});
      assert.equal(opts.method,'GET');
      assert.equal(opts.redirect,'manual');
      assert.equal(opts.credentials,'omit');
      assert.match(opts.headers.Accept,/rss\+xml/);
      assert(!('Authorization' in opts.headers));
      return new Response(rss,{headers:{'content-type':'application/rss+xml'}});
    },
    clock:()=>Date.parse('2026-11-08T00:00:00Z')
  });
  for(const source of Object.keys(FIXED)){
    const packet=await collector.get(source);
    assert.equal(packet.schema,'gateway.activity-raw/1');
    assert.equal(packet.source,source);
    assert.equal(packet.personalDataCollected,false);
    assert.equal(Buffer.from(packet.data.body,'base64url').toString('utf8'),rss);
    assert.equal(calls.at(-1).url,FIXED[source]);
  }
  assert.equal(calls.length,Object.keys(FIXED).length);
  await assert.rejects(()=>collector.get('arbitrary_news'),/invalid-source/);
});
