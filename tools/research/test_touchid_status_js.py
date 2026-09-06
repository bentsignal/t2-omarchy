# SPDX-License-Identifier: MIT
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which("node"), "Node required for shared UI model tests")
class UiModelTests(unittest.TestCase):
    def test_ready_requires_current_sensor_cue_and_available_transport(self):
        program = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const model = vm.createContext({});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), model);
const now = 100000;
const transport = {schema_version:1, channel:'transport',state:'available',updated_at:98};
const scan = {schema_version:1,channel:'scan',state:'ready',updated_at:99};
assert.equal(model.describe(transport,scan,now).ready,true);
assert.equal(model.describe(transport,scan,now,false,0,true).ready,false);
assert.equal(model.describe(transport,scan,now,false,0,true).waitingForTransport,true);
assert.equal(model.recoveredAfter(transport,98),false);
assert.equal(model.recoveredAfter(transport,97),true);
for (const state of ['sleeping','recovering','unavailable'])
 assert.equal(model.recoveredAfter({...transport,state,updated_at:100},99),false);
assert.equal(model.recoveredAfter({...transport,channel:'scan',updated_at:100},99),false);
assert.equal(model.describe(transport,scan,now,true).ready,false);
assert.equal(model.describe(transport,scan,now,true).waitingForTransport,true);
assert.equal(model.describe(transport,scan,now,false,99.5).ready,false);
assert.equal(model.describe(transport,{...scan,updated_at:99.6},now,false,99.5).ready,true);
assert.equal(model.describe({...transport,state:'sleeping',updated_at:0},scan,now).waitingForTransport,true);
assert.equal(model.describe({...transport,state:'sleeping',updated_at:0},scan,now).ready,false);
for (const state of ['sleeping','recovering','unavailable']) {
 const result = model.describe({...transport,state},scan,now);
 assert.equal(result.ready,false);
 assert.equal(result.waitingForTransport,state !== 'unavailable');
}
for (const updated_at of [0,101,97])
 assert.equal(model.describe(transport,{...scan,updated_at},now).ready,false);
for (const state of ['starting','idle','unavailable','garbage'])
 assert.equal(model.describe(transport,{...scan,state},now).ready,false);
assert.equal(model.describe({},scan,now).ready,false);
assert.equal(model.describe({...transport,state:'recovering',updated_at:0},scan,now).waitingForTransport,false);
for (const input of ['', 'null', '{}', '{"schema_version":2}', 'invalid'])
 assert.equal(model.describe(model.parse(input),scan,now).ready,false);
'''
        subprocess.run([shutil.which("node"), "-e", program, str(Path(__file__).with_name("TouchIdStatus.js"))], check=True, timeout=10)
