# Section IV Draft

## IV. Empirical Study of Runtime Trust Cascades

This section operationalizes the security issues summarized in Table I using the trust surfaces and amplification mechanisms defined in Section III. Our goal is not to infer confirmed attacks, but to measure how often structurally risky runtime trust conditions arise in real GitHub Actions workflows and how broadly their downstream consequences may extend.

### A. Study Setup

We adopt a consumer-first sampling strategy. Starting from 2,000 high-value public repositories, we collect workflow snapshots, expand direct and transitive Action dependencies, recover reusable-workflow edges, and aggregate workflow-, job-, reference-, and owner-level signals into analysis outputs. This design allows us to study runtime trust from the perspective most relevant to downstream consumers: the repository workflows that delegate execution to external components and may inherit transitive trust they do not directly expose in top-level YAML.

### B. RQ1: Hidden Transitive Trust

RQ1 focuses on hidden transitive execution, a security-relevant issue primarily induced by structural trust amplification (AM1). The central question is whether top-level workflow definitions faithfully represent the effective runtime trust surface.

Across 8,413 workflows, 1,178 exhibit a non-zero implicit dependency ratio, meaning that 14.0\% of workflows execute transitive components that are not directly visible in top-level `uses:` declarations. The depth profile further shows that multi-hop execution is not rare: 1,117 workflows reach maximum cascade depth 2 and 80 reach depth 3 or above. Representative cases are highly skewed toward release and automation-heavy pipelines; for example, `balena-io/etcher` reaches an implicit dependency ratio of 97.6\%.

These results indicate that workflow-local inspection systematically understates the true runtime trust surface of GitHub Actions. In practice, visible top-level references provide only a lower bound on the effective execution boundary.

### C. RQ2: Silent Trust Rebinding

RQ2 focuses on silent trust rebinding, the issue most directly associated with the binding stability surface (TS2). Here, the key concern is whether mutable references allow runtime trust to change without visible consumer-side workflow modification.

Mutable references remain dominant in the analyzed workflows: 17,795 of 27,621 observed bindings are mutable, corresponding to 64.4\% of all references. Across cumulative longitudinal observations, 9 upstream actions exhibit confirmed drift, affecting 2,340 drifted references and 1,521 downstream repositories. Explicit downstream updates lag upstream drift by 143.6 hours on average, whereas implicit adoption through mutable bindings is effectively immediate. Exposure-window analysis further identifies 10 explicit drift exposure windows, with an average duration of 129.1 hours.

Together, these results show that mutable references do more than trade off convenience and reproducibility. They create a silent trust-rebinding channel in which a workflow's visible reference string can remain unchanged while the runtime code it executes shifts over time.

### D. RQ3: Shared Runtime and Privilege Coupling

RQ3 focuses on shared-runtime co-location and privilege coupling. These issues emerge when mixed-trust execution in the shared runtime surface (TS3) intersects with sensitive workflow capabilities in the privileged execution surface (TS4).

At the job level, mixed-trust execution is common: 8,170 of 15,509 jobs (52.7\%) span multiple trust domains, and 1,574 jobs place third-party Actions before sensitive execution steps. Shared-state signals are also frequent, including 1,513 jobs with environment-pollution signals, 4,080 with output-dependency signals, and 10,552 with filesystem-sharing signals. At the privilege layer, 791 workflows request `id-token: write`, 527 use `pull_request_target`, and 999 jobs combine mutable third-party dependencies with privileged execution. More broadly, 4,508 jobs exhibit isolation-privilege coupling.

These findings suggest that in real workflows, third-party execution is often not strongly isolated from sensitive CI/CD contexts. The more consequential risk is not privilege alone, but privilege co-located with shared-runtime trust exposure.

### E. RQ4: Cross-Context Propagation

RQ4 focuses on cross-context propagation, the issue most directly associated with the propagation surface (TS5). The key question is whether workflow-native channels such as artifacts, outputs, and reusable workflows allow local trust consequences to extend beyond their original execution context.

Propagation channels are widespread. Among 8,408 workflows, 1,366 upload artifacts, 688 download artifacts, 769 use cache save/restore, 823 define job outputs, and 1,881 consume `needs.outputs`. Workflow-level reuse adds another important boundary layer: we identify 1,308 reusable-workflow edges, including 290 remote edges, 205 mutable edges, 376 edges with `secrets: inherit`, and 733 edges carrying explicit permissions. Overall, 3,573 workflows exhibit privilege-propagation coupling.

This evidence shows that runtime trust consequences do not remain confined to a single step or job. Instead, GitHub Actions workflows routinely expose channels through which attacker-influenced state may cross job, workflow, repository, and organizational boundaries.

### F. RQ5: Systemic Downstream Amplification

RQ5 focuses on ecosystem-scale amplification. This issue is jointly induced by structural trust amplification (AM1) and concentration-based trust amplification (AM2), which capture how hidden dependency structure and concentrated reuse can transform local trust failures into disproportionately broad downstream exposure.

Concentration is pronounced at both the Action and owner levels. The top 100 actions account for 44.1\% of observed action usage, with an action-usage Gini coefficient of 0.9052. At the owner level, the top 1 owner covers 58.2\% of observed owner usage, while the top 10 cover 75.1\%, with a Gini coefficient of 0.9172. Structural comparisons further show that cross-owner workflows are riskier than same-owner workflows: their average mutable-reference ratio is 66.9\% versus 18.0\%, their average privilege-risk score is 5.76 versus 2.28, and their average propagation-channel count is 1.24 versus 0.60.

These results indicate that runtime trust exposure in GitHub Actions is not evenly distributed. Local trust failures are amplified not only by hidden execution structure, but also by concentrated ecosystem dependence on a relatively small set of Actions and maintainers.
