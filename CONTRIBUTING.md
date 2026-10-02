# Contributing to DETOX Rate Limiting

Thank you for your interest in contributing to DETOX! We welcome all contributions — from bug reports and documentation fixes to new features and performance improvements.

## 🚀 Getting Started

### 1. Fork & Clone

```bash
git clone https://github.com/<your-username>/detox-ratelimit.git
cd detox-ratelimit
npm install
```

### 2. Build

```bash
npm run build
```

### 3. Run Tests

```bash
npm test
```

All tests must pass before submitting a PR.

## 📋 Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```
2. Make changes in `src/`
3. Add tests for your changes in `tests/`
4. Run `npm run build && npm test`
5. Commit with a descriptive message
6. Push and open a Pull Request

## 🏗️ Project Structure

```
src/
├── core/           # Engine, types, token generator, hasher
│   ├── engine.ts   # DetoxRateLimiter class
│   ├── types.ts    # TypeScript interfaces
│   ├── token.ts    # Binary Security Key generator
│   └── hasher.ts   # FNV-1a credential hasher
├── stores/         # Pluggable storage backends
│   ├── memory.ts   # In-memory store (zero dependencies)
│   └── redis.ts    # Distributed Redis store with Lua scripts
├── client/         # Browser-side 0-Cache Shield
│   ├── zero-cache.ts
│   └── index.ts
├── middleware/     # Framework integrations
│   ├── express.ts  # Express/Connect middleware
│   └── nextjs.ts   # Next.js App Router helper
└── index.ts       # Main entry point
```

## 📐 Code Standards

- **TypeScript**: All source code is written in strict TypeScript
- **Zero runtime dependencies**: The core library must not introduce any required npm dependencies
- **Documentation**: Every public function and class must have JSDoc comments
- **Tests**: All new features must include corresponding tests

## 🐛 Reporting Issues

- Use the [GitHub Issues](https://github.com/detox-engineering/detox-ratelimit/issues) page
- Include reproduction steps, expected behavior, and actual behavior
- Include your Node.js version, OS, and framework (Express/Next.js)

## 📄 License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
