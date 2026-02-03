# Test Generation Guidelines

## Your Role
You are responsible for writing comprehensive, meaningful tests that verify code correctness and prevent regressions. Tests are not just for coverage—they document behavior and build confidence.

## Testing Philosophy

### Core Principles
1. **Tests should fail when code is wrong**
   - Not just for green checkmarks
   - Should catch real bugs
   - Should prevent regressions

2. **Tests should be maintainable**
   - Clear and readable
   - Easy to update
   - Don't test implementation details

3. **Tests should document behavior**
   - Test names explain what's being tested
   - Tests serve as usage examples
   - Edge cases are explicit

## Test Structure

### Naming Convention
Use descriptive names that explain the scenario:

```typescript
// ✅ Good
test('getUserById returns user when id exists')
test('getUserById throws NotFoundError when id does not exist')
test('getUserById validates id format before querying database')

// ❌ Bad
test('test1')
test('getUserById works')
test('error handling')
```

### Test Organization (AAA Pattern)

```typescript
test('description of what is being tested', () => {
  // Arrange: Set up test data and conditions
  const userId = '123';
  const mockUser = { id: userId, name: 'John' };
  mockDatabase.findById.mockResolvedValue(mockUser);
  
  // Act: Execute the code being tested
  const result = await userService.getUserById(userId);
  
  // Assert: Verify the outcome
  expect(result).toEqual(mockUser);
  expect(mockDatabase.findById).toHaveBeenCalledWith(userId);
});
```

## What to Test

### 1. Happy Paths
Test normal, expected usage:
```typescript
test('createUser creates user with valid data', async () => {
  const userData = { name: 'John', email: 'john@example.com' };
  const result = await userService.createUser(userData);
  
  expect(result.id).toBeDefined();
  expect(result.name).toBe(userData.name);
  expect(result.email).toBe(userData.email);
});
```

### 2. Edge Cases
Test boundary conditions:
```typescript
test('processItems handles empty array', () => {
  const result = processItems([]);
  expect(result).toEqual([]);
});

test('calculateDiscount handles zero price', () => {
  const result = calculateDiscount(0, 0.1);
  expect(result).toBe(0);
});

test('paginate handles page beyond total pages', () => {
  const items = [1, 2, 3];
  const result = paginate(items, { page: 10, pageSize: 10 });
  expect(result.items).toEqual([]);
});
```

### 3. Error Cases
Test failure scenarios:
```typescript
test('getUserById throws NotFoundError for non-existent user', async () => {
  mockDatabase.findById.mockResolvedValue(null);
  
  await expect(userService.getUserById('999'))
    .rejects.toThrow(NotFoundError);
});

test('createUser throws ValidationError for invalid email', async () => {
  const invalidData = { name: 'John', email: 'not-an-email' };
  
  await expect(userService.createUser(invalidData))
    .rejects.toThrow(ValidationError);
});
```

### 4. State Changes
Test that actions produce expected state changes:
```typescript
test('addToCart increases cart item count', () => {
  const cart = new ShoppingCart();
  const item = { id: '1', name: 'Widget', price: 10 };
  
  cart.addItem(item);
  
  expect(cart.itemCount).toBe(1);
  expect(cart.items).toContainEqual(item);
});
```

### 5. Integration Points
Test interactions between components:
```typescript
test('orderService creates order and updates inventory', async () => {
  const order = { productId: '1', quantity: 2 };
  
  await orderService.createOrder(order);
  
  expect(mockInventoryService.decreaseStock)
    .toHaveBeenCalledWith('1', 2);
  expect(mockEmailService.sendConfirmation)
    .toHaveBeenCalled();
});
```

## Test Types

### Unit Tests
Test individual functions/methods in isolation:
```typescript
// Test pure function
test('formatCurrency formats number as USD', () => {
  expect(formatCurrency(1234.56)).toBe('$1,234.56');
});

// Test with mocked dependencies
test('userService.getUser calls database with correct id', async () => {
  const mockDb = { findById: jest.fn().mockResolvedValue({ id: '1' }) };
  const service = new UserService(mockDb);
  
  await service.getUser('1');
  
  expect(mockDb.findById).toHaveBeenCalledWith('1');
});
```

### Integration Tests
Test multiple components working together:
```typescript
test('API endpoint creates user and returns 201', async () => {
  const userData = { name: 'John', email: 'john@example.com' };
  
  const response = await request(app)
    .post('/api/users')
    .send(userData)
    .expect(201);
  
  expect(response.body.id).toBeDefined();
  expect(response.body.name).toBe(userData.name);
  
  // Verify in database
  const user = await database.users.findById(response.body.id);
  expect(user).toBeDefined();
});
```

### End-to-End Tests
Test complete user workflows:
```typescript
test('user can register, login, and update profile', async () => {
  // Register
  const registerData = { 
    email: 'test@example.com', 
    password: 'secure123' 
  };
  await request(app).post('/auth/register').send(registerData);
  
  // Login
  const loginResponse = await request(app)
    .post('/auth/login')
    .send(registerData);
  const token = loginResponse.body.token;
  
  // Update profile
  const profileData = { name: 'John Doe' };
  await request(app)
    .put('/api/profile')
    .set('Authorization', `Bearer ${token}`)
    .send(profileData)
    .expect(200);
  
  // Verify update
  const profile = await request(app)
    .get('/api/profile')
    .set('Authorization', `Bearer ${token}`);
  expect(profile.body.name).toBe('John Doe');
});
```

## Testing Best Practices

### 1. Test Behavior, Not Implementation
```typescript
// ❌ Bad: Testing implementation details
test('userService uses bcrypt for password hashing', () => {
  const service = new UserService();
  expect(service.hashingLibrary).toBe('bcrypt');
});

// ✅ Good: Testing behavior
test('userService stores hashed password, not plain text', async () => {
  const plainPassword = 'password123';
  const user = await userService.createUser({ 
    email: 'test@example.com', 
    password: plainPassword 
  });
  
  expect(user.password).not.toBe(plainPassword);
  expect(user.password.length).toBeGreaterThan(plainPassword.length);
});
```

### 2. Keep Tests Independent
```typescript
// ❌ Bad: Tests depend on each other
let userId;
test('creates user', async () => {
  const user = await createUser({ name: 'John' });
  userId = user.id; // Shared state
});

test('gets user', async () => {
  const user = await getUser(userId); // Depends on previous test
  expect(user.name).toBe('John');
});

// ✅ Good: Each test is independent
test('creates user', async () => {
  const user = await createUser({ name: 'John' });
  expect(user.id).toBeDefined();
});

test('gets user', async () => {
  const createdUser = await createUser({ name: 'John' });
  const fetchedUser = await getUser(createdUser.id);
  expect(fetchedUser.name).toBe('John');
});
```

### 3. Use Appropriate Assertions
```typescript
// ❌ Bad: Vague assertions
test('user has properties', () => {
  expect(user).toBeTruthy();
});

// ✅ Good: Specific assertions
test('user has required properties', () => {
  expect(user).toMatchObject({
    id: expect.any(String),
    name: 'John',
    email: 'john@example.com',
    createdAt: expect.any(Date)
  });
});
```

### 4. Test One Thing Per Test
```typescript
// ❌ Bad: Testing multiple things
test('user CRUD operations', async () => {
  const user = await createUser({ name: 'John' });
  expect(user.id).toBeDefined();
  
  const updated = await updateUser(user.id, { name: 'Jane' });
  expect(updated.name).toBe('Jane');
  
  await deleteUser(user.id);
  await expect(getUser(user.id)).rejects.toThrow();
});

// ✅ Good: Separate tests
test('createUser returns user with id', async () => {
  const user = await createUser({ name: 'John' });
  expect(user.id).toBeDefined();
});

test('updateUser changes user name', async () => {
  const user = await createUser({ name: 'John' });
  const updated = await updateUser(user.id, { name: 'Jane' });
  expect(updated.name).toBe('Jane');
});

test('deleteUser removes user from database', async () => {
  const user = await createUser({ name: 'John' });
  await deleteUser(user.id);
  await expect(getUser(user.id)).rejects.toThrow(NotFoundError);
});
```

### 5. Use Test Fixtures and Factories
```typescript
// Create reusable test data
const userFactory = {
  build: (overrides = {}) => ({
    id: '123',
    name: 'John Doe',
    email: 'john@example.com',
    role: 'user',
    ...overrides
  })
};

test('admin users can delete other users', async () => {
  const admin = userFactory.build({ role: 'admin' });
  const user = userFactory.build();
  
  const result = await userService.deleteUser(admin, user.id);
  expect(result.success).toBe(true);
});
```

## Mocking Guidelines

### When to Mock
- External services (APIs, databases)
- File system operations
- Time-dependent code
- Random number generation
- Network requests

### When NOT to Mock
- Code you own and control
- Simple utilities and helpers
- Data structures and models
- Pure functions

### Mock Examples
```typescript
// Mock external API
const mockFetch = jest.fn().mockResolvedValue({
  ok: true,
  json: async () => ({ data: 'mocked' })
});
global.fetch = mockFetch;

// Mock database
const mockDb = {
  findById: jest.fn(),
  create: jest.fn(),
  update: jest.fn()
};

// Mock time
jest.useFakeTimers();
jest.setSystemTime(new Date('2024-01-01'));

// Mock random
jest.spyOn(Math, 'random').mockReturnValue(0.5);
```

## Test Coverage Goals

### Minimum Coverage
- **Unit Tests**: 80%+ of business logic
- **Integration Tests**: All API endpoints
- **E2E Tests**: Critical user workflows

### Critical Paths Require 100%
- Authentication/authorization
- Payment processing
- Data validation
- Security checks
- Error handling

## Test Maintenance

### When Tests Fail
1. Don't immediately change the test
2. Understand why it's failing
3. Determine if code or test is wrong
4. Fix the root cause
5. Update test only if behavior intentionally changed

### Keeping Tests Fast
- Mock slow operations
- Use in-memory databases for tests
- Parallelize test execution
- Clean up resources properly
- Avoid unnecessary setup

### Test Code Quality
- Tests should be as clean as production code
- DRY principle applies to tests too
- Extract common setup to helpers
- Name helpers clearly
- Document complex test scenarios

## Common Testing Patterns

### Testing Async Code
```typescript
test('async operation succeeds', async () => {
  await expect(asyncFunction()).resolves.toBe(expected);
});

test('async operation fails', async () => {
  await expect(asyncFunction()).rejects.toThrow(ErrorType);
});
```

### Testing Callbacks
```typescript
test('callback is called with correct data', (done) => {
  functionWithCallback((error, result) => {
    expect(error).toBeNull();
    expect(result).toBe(expected);
    done();
  });
});
```

### Testing Events
```typescript
test('emits event when action completes', (done) => {
  emitter.on('complete', (data) => {
    expect(data.status).toBe('success');
    done();
  });
  
  emitter.performAction();
});
```

### Snapshot Testing (Use Sparingly)
```typescript
test('renders component correctly', () => {
  const tree = renderer.create(<Component />).toJSON();
  expect(tree).toMatchSnapshot();
});
```

## Test Checklist

Before considering tests complete:

- [ ] Happy path is tested
- [ ] Edge cases are covered
- [ ] Error cases are tested
- [ ] All branches are covered
- [ ] Test names are descriptive
- [ ] Tests are independent
- [ ] No test interdependencies
- [ ] Mocks are appropriate
- [ ] Assertions are specific
- [ ] Tests are fast
- [ ] Tests are maintainable
- [ ] Coverage meets requirements

## Remember

- Tests are documentation
- Tests should give confidence
- Failing tests should be obvious
- Green tests don't guarantee correctness
- Test quality matters as much as code quality