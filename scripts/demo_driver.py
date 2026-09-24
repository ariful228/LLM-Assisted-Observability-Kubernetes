import argparse
import sys
import time

from backend.services import simulation, store
from backend.services.detector import detect
from backend.workflows.graph import reset_graphs, resume_workflow, run_workflow


def main() -> None:
    parser = argparse.ArgumentParser(description="Demo driver for the AI Kubernetes Observability platform")
    parser.add_argument("--reset", action="store_true", help="Reset simulated cluster + incident store")
    parser.add_argument("--detect", action="store_true", help="Run detection for all six scenarios")
    parser.add_argument("--approve-all", action="store_true", help="Approve every pending approval")
    parser.add_argument("--reject-all", action="store_true", help="Reject every pending approval")
    parser.add_argument("--list", action="store_true", help="List incidents")
    args = parser.parse_args()

    if args.reset:
        simulation.reset_simulation()
        store.reset_store()
        reset_graphs()
        print("reset complete")

    if args.detect:
        reset_graphs()
        store_obj = store.get_store()
        ot = time.time()
        for shell in detect():
            shell.incident_id = store_obj.next_incident_id()
            store_obj.create(shell)
            done = run_workflow(shell.incident_id)
            decision = done.policy_decision.decision if done.policy_decision else "no_action"
            print(f"  {done.incident_id:<12} type={done.incident_type.value:<18} decision={decision}")
        print(f"detected in {1000 * (time.time() - ot):.0f} ms")

    if args.approve_all:
        for inc in store.get_store().list():
            if inc.approval_status and inc.approval_status.value == "PENDING":
                done = resume_workflow(inc.incident_id, decision="approve", approved_by="demo-cli")
                action = done.recommended_action.action if done.recommended_action else "-"
                print(f"  approved {done.incident_id} -> {action}: {done.status.value}/{done.verification_status.value}")

    if args.reject_all:
        for inc in store.get_store().list():
            if inc.approval_status and inc.approval_status.value == "PENDING":
                done = resume_workflow(inc.incident_id, decision="reject", approved_by="demo-cli", reason="manual test")
                print(f"  rejected {done.incident_id}: {done.status.value}")

    if args.list:
        for i in store.get_store().list():
            pd = i.policy_decision
            print(f"  {i.incident_id:<12} {i.incident_type.value:<18} {i.status.value:<16} policy={pd.decision.value if pd else '-'} exec={i.execution_status.value} verify={i.verification_status.value}")


if __name__ == "__main__":
    sys.exit(main())