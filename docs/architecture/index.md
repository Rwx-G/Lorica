# Lorica Brownfield Enhancement Architecture

**Author:** Romain G.
**Date:** 2026-03-28
**Status:** Draft
**Version:** 1.0

---

This document outlines the architectural approach for transforming Cloudflare's Pingora framework into Lorica, a dashboard-first, self-administered reverse proxy product. Its primary goal is to serve as the guiding architectural blueprint for AI-driven development of new features while ensuring seamless integration with the existing Pingora proxy engine.

**Relationship to Existing Architecture:**
This document supplements the Pingora framework architecture by defining how new product components (API, dashboard, config state, worker isolation, WAF) integrate with the existing proxy engine. Where conflicts arise between new patterns and Pingora's framework design, this document provides guidance on maintaining proxy engine integrity while building the product layer.

## Sections

- [Introduction](./introduction.md)
- [Enhancement Scope and Integration Strategy](./enhancement-scope-and-integration-strategy.md)
- [Tech Stack](./tech-stack.md)
- [Data Models and Schema Changes](./data-models-and-schema-changes.md)
- [Component Architecture](./component-architecture.md)
- [API Design and Integration](./api-design-and-integration.md)
- [Source Tree](./source-tree.md)
- [Infrastructure and Deployment](./infrastructure-and-deployment.md)
- [Coding Standards](./coding-standards.md)
- [Testing Strategy](./testing-strategy.md)
- [Security Integration](./security-integration.md)
- [Checklist Results Report](./checklist-results-report.md)
- [Next Steps](./next-steps.md)
