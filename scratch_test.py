"""Module 6 smoke test: SOC engine ingest, enrich, SIEM, MITRE, persistence."""
from core.network.enterprise import EnterpriseNetworkBuilder
from core.attacks.simulator import AttackSimulator
from core.soc.engine import SocEngine
from core.soc.siem import SiemQuery
from core.enums import Severity
from database.connection import Database
from database.repository import SocRepository


def banner(t):
    print("\n" + "=" * 60)
    print(t)
    print("=" * 60)


def main():
    topo = EnterpriseNetworkBuilder().build()
    sim = AttackSimulator(topo, seed=7)
    soc = SocEngine()

    banner("Running attacks and feeding the SOC")
    runs = [
        ("nmap", "ATTACKER", "WEB-01"),
        ("sqli", "ATTACKER", "WEB-01"),
        ("rdp_brute", "ATTACKER", "WS-IT-01"),
        ("ssh_brute", "REMOTE-USER", "APP-01"),
    ]
    for key, src, dst in runs:
        result = sim.run(key, source=src, target=dst)
        produced = soc.ingest_attack(result)
        print(f"{key:10s} {src:12s} -> {dst:10s} "
              f"events={len(result.events):3d} alerts={len(produced)}")

    banner("SOC dashboard stats")
    for k, v in soc.stats().items():
        print(f"{k:16s}: {v}")

    banner("Enriched alerts (top by severity)")
    for a in sorted(soc.alerts(), key=lambda x: int(x.severity), reverse=True)[:4]:
        print(f"\n[{a.severity.label}] {a.title}")
        print(f"  MITRE   : {a.mitre_id} ({a.tactic})")
        print(f"  IOCs    : {[i.value for i in a.iocs]}")
        print(f"  Contain : {a.containment[0] if a.containment else '-'}")
        print(f"  Impact  : {a.business_impact}")

    banner("SIEM query: HIGH+ severity events")
    for e in soc.siem.search(SiemQuery(min_severity=Severity.HIGH))[:6]:
        print(f"  [{e.severity.label:8s}] {e.source:12s} {e.message[:55]}")

    banner("MITRE ATT&CK rollup")
    for t in soc.mitre().techniques():
        print(f"  {t.technique_id:8s} {t.name:34s} x{t.count}  ({t.tactic})")

    banner("SQLite persistence round-trip (in-memory DB)")
    repo = SocRepository(Database(":memory:"))
    soc2 = SocEngine(repository=repo)
    for key, src, dst in runs:
        soc2.ingest_attack(sim.run(key, source=src, target=dst))
    print("persisted   :", repo.counts())
    print("reload alerts:", len(repo.load_alerts()))
    print("reload events:", len(repo.load_events()))

    print("\nModule 6 OK")


if __name__ == "__main__":
    main()
