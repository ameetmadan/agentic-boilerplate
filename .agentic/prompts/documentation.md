# Documentation Generation Guidelines

## Your Role
You are responsible for creating clear, accurate, and useful documentation that helps developers understand and use the codebase effectively. Documentation should make code accessible, not just describe it.

## Documentation Philosophy

### Core Principles
1. **Write for humans first**
   - Clear language over technical jargon
   - Examples over abstract descriptions
   - Practical over comprehensive

2. **Keep documentation close to code**
   - Update docs when code changes
   - Inline documentation for complex logic
   - Module READMEs for context

3. **Don't repeat the code**
   - Explain why, not what
   - Document intent and decisions
   - Clarify non-obvious behavior

## Documentation Types

### 1. Code Comments

#### When to Use Comments
```typescript
// ✅ Good: Explains WHY
// Using exponential backoff to prevent overwhelming the API
// during recovery from network issues
await retryWithBackoff(apiCall, { maxRetries: 3 });

// ✅ Good: Clarifies non-obvious behavior
// Note: This returns null for missing keys (not undefined)
// to maintain consistency with the external API
const value = cache.get(key);

// ✅ Good: Warns about gotchas
// IMPORTANT: Must call initialize() before use or database
// connections will fail silently
class DatabaseService {
  // ...
}

// ❌ Bad: Repeats the code
// Set user name to John
userName = 'John';

// ❌ Bad: States the obvious
// Loop through items
for (const item of items) {
  // ...
}
```

#### Comment Style
```typescript
/**
 * Single-line comments for brief explanations
 */

/**
 * Multi-line comments for:
 * - Complex algorithms
 * - Business logic
 * - Important context
 */

// TODO: Add pagination support
// FIXME: This breaks when array is empty
// HACK: Temporary workaround until API is fixed
// NOTE: Keep this synchronized with the mobile app
```

### 2. Function Documentation

#### JSDoc/TypeDoc Format
```typescript
/**
 * Retrieves a user by their ID from the database.
 * 
 * @param userId - The unique identifier of the user
 * @param options - Optional query parameters
 * @param options.includeDeleted - Whether to include soft-deleted users
 * @returns The user object if found
 * @throws {NotFoundError} When user doesn't exist
 * @throws {ValidationError} When userId format is invalid
 * 
 * @example
 * ```typescript
 * const user = await getUserById('123');
 * console.log(user.name);
 * ```
 * 
 * @example Including deleted users
 * ```typescript
 * const user = await getUserById('123', { includeDeleted: true });
 * ```
 */
async function getUserById(
  userId: string, 
  options?: { includeDeleted?: boolean }
): Promise<User> {
  // Implementation
}
```

#### What to Document
```typescript
// ✅ Public APIs - Always document
export function publicFunction() { }

// ✅ Complex logic - Document the approach
function complexAlgorithm() {
  /**
   * Uses binary search to find the insertion point.
   * Time complexity: O(log n)
   */
}

// ❌ Private simple functions - Usually skip
function add(a: number, b: number) {
  return a + b; // Self-explanatory
}

// ✅ Configuration objects - Document options
interface Config {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  
  /** Delay between retries in milliseconds (default: 1000) */
  retryDelay?: number;
}
```

### 3. Module README Files

#### Structure
```markdown
# Module Name

## Purpose
Brief description of what this module does and why it exists.

## Key Concepts
Any domain-specific terminology or concepts needed to understand this module.

## Architecture
How this module fits into the larger system.

## Main Components

### ComponentA
What it does and when to use it.

### ComponentB
What it does and when to use it.

## Usage Examples

### Basic Usage
```[language]
// Simple example showing common use case
```

### Advanced Usage
```[language]
// Example showing more complex scenarios
```

## API Reference
Link to detailed API docs or inline documentation.

## Testing
Where tests are located and how to run them.

## Common Patterns
Established patterns for using this module.

## Known Issues / Limitations
Any gotchas or constraints users should know about.

## Dependencies
- External: List external dependencies
- Internal: List internal module dependencies

## Related Modules
Links to related modules and how they interact.
```

#### Example Module README
```markdown
# User Authentication Module

## Purpose
Handles user authentication, session management, and authorization checks throughout the application.

## Key Concepts
- **Session**: A temporary authentication state linked to a token
- **Refresh Token**: Long-lived token used to obtain new access tokens
- **Permission**: Granular access control (e.g., "users:read", "orders:write")

## Architecture
This module sits between the API layer and business logic, intercepting requests to verify authentication and authorization before allowing access.

```
API Request → Auth Middleware → Business Logic
                    ↓
              Token Validation
              Permission Check
```

## Main Components

### `AuthService`
Core authentication logic including login, logout, token generation, and validation.

### `AuthMiddleware`
Express middleware that protects routes and validates tokens.

### `PermissionGuard`
Checks if authenticated user has required permissions for an action.

## Usage Examples

### Protecting a Route
```typescript
import { authMiddleware, requirePermission } from './auth';

router.get('/admin/users', 
  authMiddleware,
  requirePermission('users:read'),
  async (req, res) => {
    // User is authenticated and has permission
  }
);
```

### Manual Token Validation
```typescript
import { AuthService } from './auth';

const authService = new AuthService();
const user = await authService.validateToken(token);
if (user) {
  // Token is valid
}
```

## Testing
- Unit tests: `tests/unit/auth/`
- Integration tests: `tests/integration/auth/`
- Run: `npm test -- auth`

## Common Patterns

### Checking Permissions in Service Layer
```typescript
class UserService {
  async deleteUser(actingUser: User, targetUserId: string) {
    if (!actingUser.hasPermission('users:delete')) {
      throw new UnauthorizedError();
    }
    // Proceed with deletion
  }
}
```

## Known Issues / Limitations
- Tokens are not revocable before expiration
- Maximum session duration is 24 hours
- Permission changes require re-login to take effect

## Dependencies
- External: `jsonwebtoken`, `bcrypt`
- Internal: `database`, `config`, `logger`

## Related Modules
- `user` - User data and management
- `session` - Session storage backend
- `audit` - Logs authentication events
```

### 4. API Documentation

#### REST API Documentation
```markdown
## GET /api/users/:id

Retrieves a single user by ID.

### Parameters
- `id` (path, required) - User ID

### Query Parameters
- `fields` (optional) - Comma-separated list of fields to return
- `include` (optional) - Related resources to include (e.g., "posts,comments")

### Response

#### Success (200 OK)
```json
{
  "id": "123",
  "name": "John Doe",
  "email": "john@example.com",
  "createdAt": "2024-01-01T00:00:00Z"
}
```

#### Not Found (404)
```json
{
  "error": "UserNotFound",
  "message": "User with ID '123' does not exist"
}
```

### Example Request
```bash
curl -X GET https://api.example.com/api/users/123 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Notes
- Requires authentication
- Requires `users:read` permission
- Soft-deleted users are not returned by default
```

### 5. Architecture Documentation

#### ADR (Architecture Decision Record)
```markdown
# 5. Use PostgreSQL for Primary Database

Date: 2024-01-15

## Status
Accepted

## Context
We need a reliable, scalable database for our application. Key requirements:
- ACID compliance for financial transactions
- Support for complex queries and reporting
- Strong consistency guarantees
- Active community and ecosystem

We considered PostgreSQL, MySQL, and MongoDB.

## Decision
We will use PostgreSQL as our primary database.

## Consequences

### Positive
- Excellent support for complex queries and JSON data
- Strong ACID guarantees for transactions
- Rich ecosystem of tools and extensions
- Team has PostgreSQL experience
- Good performance for our expected scale

### Negative
- More complex to set up than some alternatives
- Horizontal scaling requires additional tools (like Citus)
- Slightly steeper learning curve for junior developers

### Neutral
- Need to establish connection pooling strategy
- Will use RDS in production for managed service
- May need to add read replicas as we scale

## Alternatives Considered

### MySQL
- Pros: Simpler replication, slightly faster for simple queries
- Cons: Less sophisticated query optimizer, weaker JSON support
- Rejected because: PostgreSQL's feature set better matches our needs

### MongoDB
- Pros: Schema flexibility, horizontal scaling built-in
- Cons: Eventual consistency, less suitable for transactions
- Rejected because: ACID compliance is critical for our use case
```

### 6. README Documentation

#### Project README Structure
```markdown
# Project Name

Brief tagline describing what this project does.

## Overview
2-3 sentences explaining the project's purpose and primary use case.

## Features
- Key feature 1
- Key feature 2
- Key feature 3

## Getting Started

### Prerequisites
- Node.js 18+
- PostgreSQL 14+
- Docker (optional)

### Installation
```bash
# Clone the repository
git clone https://github.com/user/project.git

# Install dependencies
npm install

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
npm run migrate

# Start development server
npm run dev
```

### Quick Start
```typescript
// Minimal example to get started
import { Project } from 'project-name';

const project = new Project();
await project.initialize();
```

## Documentation
- [Full Documentation](./docs/README.md)
- [API Reference](./docs/api/README.md)
- [Architecture](./docs/ARCHITECTURE.md)
- [Contributing](./CONTRIBUTING.md)

## Usage Examples

### Basic Example
```typescript
// Common use case example
```

### Advanced Example
```typescript
// More complex scenario
```

## Configuration
Key configuration options and their purposes.

## Development

### Running Tests
```bash
npm test
```

### Building
```bash
npm run build
```

### Linting
```bash
npm run lint
```

## Deployment
Brief overview or link to deployment documentation.

## Contributing
See [CONTRIBUTING.md](./CONTRIBUTING.md)

## License
MIT

## Support
- Documentation: https://docs.example.com
- Issues: https://github.com/user/project/issues
- Discussions: https://github.com/user/project/discussions
```

## Documentation Best Practices

### 1. Examples Over Explanations
```markdown
// ❌ Bad: Abstract explanation
The function accepts a configuration object with various options for customizing behavior.

// ✅ Good: Concrete example
```typescript
// Configure with custom retry behavior
const client = new ApiClient({
  maxRetries: 3,
  retryDelay: 1000,
  timeout: 5000
});
```
```

### 2. Update Docs With Code
```typescript
// When you change this function:
function calculatePrice(items: Item[]): number {
  // New logic that changes behavior
}

// Also update:
// - JSDoc comment above function
// - Module README if behavior changes
// - Integration guide if API changes
// - CHANGELOG for version notes
```

### 3. Document Gotchas
```markdown
## Important Notes

⚠️ **Performance**: This operation loads the entire dataset into memory. For large datasets (>10k records), use `processInBatches()` instead.

⚠️ **Thread Safety**: This class is not thread-safe. Use separate instances for concurrent operations.

⚠️ **Breaking Change**: Version 2.0 changed the return type from `string` to `Promise<string>`. Update your code accordingly.
```

### 4. Include Diagrams When Helpful
```markdown
## Request Flow

```
User Request
    ↓
API Gateway
    ↓
Auth Middleware ──→ Validates Token
    ↓
Route Handler
    ↓
Service Layer ──→ Business Logic
    ↓
Repository ──→ Database
    ↓
Response
```
```

### 5. Version Your Docs
```markdown
## Version 2.1.0 Documentation

For older versions:
- [v2.0.x docs](./v2.0/README.md)
- [v1.x docs](./v1.0/README.md)
```

## Documentation Checklist

### For New Features
- [ ] Public API has JSDoc comments
- [ ] Usage examples provided
- [ ] Edge cases documented
- [ ] Error conditions explained
- [ ] Module README updated
- [ ] CHANGELOG entry added
- [ ] Migration guide if breaking change

### For Bug Fixes
- [ ] CHANGELOG entry added
- [ ] Related documentation corrected
- [ ] Example code updated if affected

### For Refactoring
- [ ] Architecture docs updated
- [ ] ADR created if significant
- [ ] No documentation orphaned

## Common Documentation Mistakes

### ❌ Don't
- Write documentation that just repeats code
- Leave documentation outdated
- Use jargon without explanation
- Forget to include examples
- Document private implementation details
- Write walls of text without structure

### ✅ Do
- Explain why, not just what
- Keep docs synchronized with code
- Define terms clearly
- Show practical examples
- Focus on public APIs
- Use headings and formatting

## Tools and Automation

### Documentation Generation
```typescript
// Use TypeDoc for API documentation
npm run docs:generate

// Generate markdown from JSDoc
npm run docs:api

// Check for missing documentation
npm run docs:check
```

### Documentation Testing
```typescript
// Test code examples in documentation
npm run docs:test

// Verify links are valid
npm run docs:lint
```

## Remember

- Documentation is for humans, not computers
- Good code needs less documentation, but still needs some
- Examples are worth a thousand words
- Keep documentation close to the code it describes
- Update docs when you update code
- Test your examples to ensure they work