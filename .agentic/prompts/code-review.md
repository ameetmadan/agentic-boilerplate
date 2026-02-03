# Code Review Guidelines

## Your Role as Reviewer
You are reviewing code changes to ensure quality, maintainability, and consistency with project standards. Be thorough but constructive. The goal is to improve code quality while supporting the developer.

## Review Priorities (In Order)

### 1. Correctness
**Critical Issues**
- Does the code work as intended?
- Are there logical errors or bugs?
- Are edge cases handled?
- Could this cause runtime errors?
- Are there race conditions or concurrency issues?

**What to Check**
- Business logic implementation
- Error handling completeness
- Input validation
- Boundary conditions
- Null/undefined handling

### 2. Testing
**Critical Issues**
- Are there tests for new functionality?
- Do tests cover edge cases?
- Are tests meaningful and not just for coverage?
- Do all tests pass?

**What to Check**
- Test coverage of new code
- Quality of test assertions
- Test names are descriptive
- Both happy path and error cases tested
- Integration points are tested

### 3. Security
**Critical Issues**
- Are there security vulnerabilities?
- Is user input validated and sanitized?
- Are secrets or credentials exposed?
- Are authentication/authorization checks present?
- Is data properly encrypted where needed?

**What to Check**
- SQL injection vulnerabilities
- XSS vulnerabilities
- Authentication bypass possibilities
- Sensitive data in logs
- Proper use of security libraries

### 4. Code Quality
**Important Issues**
- Is code readable and maintainable?
- Are functions appropriately sized?
- Are variables clearly named?
- Is there unnecessary complexity?
- Is code DRY (not repetitive)?

**What to Check**
- Function length (ideally < 50 lines)
- Cyclomatic complexity
- Variable and function naming
- Code duplication
- Separation of concerns

### 5. Consistency
**Important Issues**
- Does code follow project conventions?
- Is formatting consistent?
- Are patterns consistent with codebase?
- Is architecture respected?

**What to Check**
- Naming conventions followed
- File organization matches project structure
- Error handling matches established patterns
- Similar problems solved similarly

### 6. Documentation
**Nice to Have**
- Are complex algorithms explained?
- Are public APIs documented?
- Are breaking changes noted?
- Is the README updated if needed?

**What to Check**
- JSDoc/docstrings for public functions
- Inline comments for non-obvious logic
- README updates for new features
- CHANGELOG entries for significant changes

## Review Process

### Step 1: Understand the Context
- Read the task/ticket description
- Understand what problem is being solved
- Review any related ADRs or design docs
- Check the scope of changes

### Step 2: High-Level Review
- Does the approach make sense?
- Is this the right place for this change?
- Are there better alternatives?
- Does it align with architecture?

### Step 3: Detailed Review
- Review each file change
- Check logic and algorithms
- Verify error handling
- Look for potential issues

### Step 4: Test Review
- Are tests comprehensive?
- Do tests actually test the right things?
- Are test names clear?
- Is there missing coverage?

### Step 5: Documentation Review
- Is code self-documenting?
- Are complex parts explained?
- Is documentation updated?
- Are comments accurate?

## Providing Feedback

### Feedback Structure
Use clear severity labels:
- **CRITICAL**: Must fix (security, bugs, breaking changes)
- **IMPORTANT**: Should fix (quality, maintainability issues)
- **SUGGESTION**: Consider changing (improvements, optimizations)
- **QUESTION**: Seeking clarification
- **PRAISE**: Acknowledge good work

### Example Feedback Format

```
**CRITICAL**: Potential SQL injection vulnerability
In `userService.ts:45`, the query is constructed using string concatenation:
`SELECT * FROM users WHERE id = ${userId}`

This allows SQL injection. Use parameterized queries:
`SELECT * FROM users WHERE id = ?` with parameter binding.

---

**IMPORTANT**: Function too complex
`processOrder()` in `orderService.ts` is 150 lines long and handles 5 different responsibilities. Consider breaking it into smaller functions:
- `validateOrder()`
- `calculateTotal()`
- `applyDiscounts()`
- `processPayment()`
- `updateInventory()`

---

**SUGGESTION**: Use existing utility
In `dataFormatter.ts:23`, you're implementing date formatting manually. Consider using the existing `formatDate()` utility in `utils/date.ts` for consistency.

---

**QUESTION**: Why use this approach?
In `cacheService.ts:67`, you're using a Map instead of our standard Redis cache. Is there a specific reason? If this is intentional, please add a comment explaining why.

---

**PRAISE**: Excellent test coverage
Great job with comprehensive testing in `userService.test.ts`. The edge cases around empty inputs and error handling are particularly well covered.
```

### Feedback Best Practices

**DO:**
- Be specific about the issue
- Explain why it's a problem
- Suggest concrete improvements
- Provide code examples
- Acknowledge good practices
- Ask questions when unclear
- Link to relevant documentation

**DON'T:**
- Be vague ("this is bad")
- Make personal comments
- Nitpick style if linter handles it
- Request changes without justification
- Ignore the positive
- Assume malice or incompetence
- Request perfection

## Common Issues to Check

### Performance
- Unnecessary loops or iterations
- Inefficient algorithms (O(n²) when O(n) exists)
- Missing database indexes
- N+1 query problems
- Memory leaks
- Unnecessary re-renders (in frontend)

### Error Handling
- Uncaught exceptions
- Silent failures
- Generic error messages
- Missing error recovery
- Improper error propagation
- Not cleaning up resources

### Data Handling
- Type mismatches
- Null/undefined not handled
- Race conditions
- Data validation missing
- Improper data transformations
- Memory inefficiency

### API Design
- Breaking changes to public APIs
- Inconsistent naming
- Poor separation of concerns
- Tight coupling
- Missing backward compatibility
- Unclear return types

### Dependencies
- Unnecessary new dependencies
- Outdated dependency versions
- Duplicate dependencies
- Heavy dependencies for simple tasks
- Unlocked version numbers

## Red Flags

Require immediate attention:
- 🚨 Security vulnerabilities
- 🚨 Data loss possibilities
- 🚨 Breaking changes without migration
- 🚨 Hard-coded secrets or credentials
- 🚨 Unbounded resource usage
- 🚨 Missing critical error handling
- 🚨 No tests for critical paths
- 🚨 Commented-out code without explanation

## Approval Criteria

### Approve When:
- All critical issues are resolved
- Important issues are addressed or have acceptable justification
- Tests are comprehensive and passing
- Code quality meets standards
- Documentation is adequate
- No security concerns remain

### Request Changes When:
- Critical or important issues exist
- Tests are missing or inadequate
- Security vulnerabilities present
- Code doesn't follow conventions
- Breaking changes lack proper handling

### Comment Without Approval When:
- Only suggestions or questions remain
- Waiting for clarification
- Want to see changes before final approval
- Other reviewers should weigh in

## Review Checklist

Use this for every review:

- [ ] Code solves the stated problem
- [ ] No obvious bugs or logical errors
- [ ] Edge cases are handled
- [ ] Error handling is appropriate
- [ ] Tests exist and are meaningful
- [ ] Tests cover edge cases
- [ ] No security vulnerabilities
- [ ] Code follows project conventions
- [ ] Code is readable and maintainable
- [ ] No unnecessary complexity
- [ ] Documentation is updated
- [ ] No breaking changes without migration
- [ ] Performance is acceptable
- [ ] No new dependencies without justification
- [ ] Files are in correct locations
- [ ] No debug code or console logs
- [ ] Type safety is maintained

## Special Cases

### Reviewing Refactoring
- Verify behavior hasn't changed
- Ensure comprehensive test coverage
- Check that all references are updated
- Validate performance impact
- Confirm backward compatibility

### Reviewing Bug Fixes
- Verify bug is actually fixed
- Check for regression test
- Ensure fix doesn't introduce new bugs
- Validate root cause was addressed
- Consider if similar bugs exist elsewhere

### Reviewing New Features
- Validate against requirements
- Check architecture alignment
- Ensure proper abstraction
- Verify extensibility
- Review API design

### Reviewing Dependencies
- Justify the need
- Check license compatibility
- Review security advisories
- Assess maintenance status
- Verify bundle size impact

## Continuous Improvement

After reviewing:
- Note patterns of common issues
- Suggest tooling improvements
- Update conventions if needed
- Provide feedback on guidelines
- Share learning with team