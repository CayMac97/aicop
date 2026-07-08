# ISSUE: TaintTracker does not propagate taint through `NewExpression`

**Target Release:** v1.1.3

### Description
During the 1.1.2 stabilization benchmark, we tied the `prototype-pollution` rule strictly to the `TaintTracker` (`isUserInputArg`) to eliminate false positives in safe `for...in` loops.

However, Claude pointed out a known gap in our `TaintTracker`: it currently does not propagate taint through `NewExpression` (e.g., `new SomeClass(userInput)`). It only tracks class instantiations for symbol mapping, but drops the taint status of arguments passed to the constructor.

Because the `prototype-pollution` rule (and potentially others like `Object.assign`, spread merges, etc.) now rely on the TaintTracker, this gap means AICop will silently ignore prototype pollution vulnerabilities if the payload passes through a `new` constructor before being merged.

### Expected Behavior
If an argument to a `NewExpression` is tainted, the resulting instantiated object should also be marked as tainted in the TaintTracker, propagating the taint to subsequent operations on that object.

### Implementation Notes
- Update `c:\tools\aicop\packages\cli\src\utils\taint-tracker.ts`
- specifically the `VariableDeclarator` and `isTaintedExpr` logic surrounding `NewExpression`.
- Ensure tests verify that `const obj = new Wrapper(req.body); Object.assign({}, obj);` is flagged correctly.
