import { readFileSync } from 'fs';

// Extract and test the escapeHtml function
const indexContent = readFileSync('./src/index.js', 'utf8');
const escapeHtmlMatch = indexContent.match(/function escapeHtml\(text\) \{[\s\S]*?return String\(text\)\.replace[\s\S]*?\}/);

if (!escapeHtmlMatch) {
  console.error('❌ escapeHtml function not found!');
  process.exit(1);
}

// Create the function
eval(`var escapeHtml = ${escapeHtmlMatch[0]}`);

// Test cases
const tests = [
  {
    input: '"><script>alert(1)</script>',
    expected: '&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;',
    description: 'Script tag XSS'
  },
  {
    input: '"><img src=x onerror=alert(5)>',
    expected: '&quot;&gt;&lt;img src=x onerror=alert(5)&gt;',
    description: 'Image tag XSS (the original vulnerability)'
  },
  {
    input: "' onmouseover='alert(1)'",
    expected: '&#039; onmouseover=&#039;alert(1)&#039;',
    description: 'Event handler XSS'
  },
  {
    input: 'example.com',
    expected: 'example.com',
    description: 'Safe domain name'
  },
  {
    input: null,
    expected: '',
    description: 'Null input'
  },
  {
    input: '',
    expected: '',
    description: 'Empty string'
  }
];

console.log('Testing escapeHtml function...\n');

let passed = 0;
let failed = 0;

tests.forEach(test => {
  const result = escapeHtml(test.input);
  if (result === test.expected) {
    console.log(`✅ ${test.description}`);
    console.log(`   Input: ${JSON.stringify(test.input)}`);
    console.log(`   Output: ${result}\n`);
    passed++;
  } else {
    console.log(`❌ ${test.description}`);
    console.log(`   Input: ${JSON.stringify(test.input)}`);
    console.log(`   Expected: ${test.expected}`);
    console.log(`   Got: ${result}\n`);
    failed++;
  }
});

// Check that parameters are being escaped in the code
const checks = [
  { pattern: 'const filter = escapeHtml(filterRaw);', param: 'filter' },
  { pattern: 'const domain = escapeHtml(domainRaw);', param: 'domain' },
  { pattern: 'const checkpoints = escapeHtml(checkpointsRaw);', param: 'checkpoints' },
  { pattern: 'const viewly = escapeHtml(viewlyRaw);', param: 'view' },
];

console.log('\nVerifying parameters are escaped in index.js...\n');

checks.forEach(check => {
  if (indexContent.includes(check.pattern)) {
    console.log(`✅ ${check.param} parameter is escaped`);
    passed++;
  } else {
    console.log(`❌ ${check.param} parameter is NOT escaped`);
    failed++;
  }
});

console.log(`\n========================================`);
console.log(`Total: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);

if (failed > 0) {
  console.error('Some tests failed!');
  process.exit(1);
} else {
  console.log('All tests passed! The XSS vulnerability has been fixed.');
}