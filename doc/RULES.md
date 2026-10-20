# ShipSafe - Development & Contribution Rules

## 1. Code Standards & Best Practices
- **Consistency**: Adhere to project linting and formatting configurations.
- **Modularity**: Follow single-responsibility principles and keep components focused and reusable.
- **Documentation**: Write clear docstrings/comments for exported functions, types, and architectural decisions. Preserve existing comments.

## 2. Git & Version Control Rules
- **Branch Strategy**:
  - `main`: Production-ready, stable codebase.
  - `feature/<name>`: New feature work.
  - `fix/<name>`: Bug fixes and patches.
  - `chore/<name>`: Tooling, dependencies, or maintenance.
- **Commit Messages**: Follow Conventional Commits format:
  - `feat: add pre-flight check runner`
  - `fix: resolve environment variable parser issue`
  - `docs: update deployment guidelines in PRD`
  - `chore: update dependencies`

## 3. Testing & Quality Assurance
- Every new feature must be accompanied by relevant unit or integration tests.
- Code coverage must remain above the established baseline.
- Never push broken tests or failing build scripts to `main`.

## 4. Security & Safety Guidelines
- **Zero Secrets in Code**: Never commit credentials, `.env` files, API keys, or private tokens to Git. Use environment variables.
- **Dependency Auditing**: Regularly audit dependencies for CVEs and vulnerability notices.
- **Fail-Closed Principle**: If safety verification fails or times out, the deployment gate remains locked.

## 5. Review & Approval Protocol
- All pull requests require at least one peer review before merging.
- Any manual overrides of safety checks must be recorded with an explicit reason.

## 6. Context Awareness & Skill Discovery
- **Comprehensive File Context**: Always reference and utilize all relevant project files (such as `doc/PRD.md`, `doc/RULES.md`, `doc/INSTABOX.md`, contracts, schemas, and configurations) before starting or modifying code. Never guess or hallucinate requirements when specifications exist in the repository.
- **Compute Infrastructure Docs**: For all cloud VM and sandbox interactions, adhere to [`doc/INSTABOX.md`](file:///d:/shipsafe/doc/INSTABOX.md) and the official documentation at [https://instabox.sh/docs](https://instabox.sh/docs).
- **Agent Skill Utilization**: Actively check and use relevant skills available under `.agents/skills/` (e.g., `design-taste-frontend`, `ui-ux-pro-max`, `improve-codebase-architecture`).
- **Dynamic Skill Acquisition (`find-skills`)**: If a task requires a specific capability, domain knowledge, or workflow and no matching local skill is found, use the `find-skills` skill to search, identify, and install the appropriate skill.

