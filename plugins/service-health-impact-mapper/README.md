# Service Health Impact Mapper

Provide one Azure Service Health tracking ID to assess potentially affected resources, health evidence, and zone resilience. Requires read access to the relevant subscriptions and monitoring sources. The skill produces an impact report and does not modify Azure resources.

The bundled Python 3.10+ helper validates tracking IDs, derives UTC investigation windows, and
pages Resource Graph inventory deterministically. See the skill's query reference for usage.
Resource discovery requires an authenticated Azure CLI in Azure public cloud; validation and
window calculation are offline. The helper uses only the Python standard library.

From the repository root, run the focused offline tests:

```bash
python -B -m unittest discover -s plugins/service-health-impact-mapper/skills/service-health-impact-mapper/scripts -p "test_*.py" -v
```
