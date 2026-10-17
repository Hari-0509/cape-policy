"""Team namespaces = namespaces carrying the label cape-policy/class=application.
Replaces the hard-coded namespace list used by the Shadowing detector."""
from kubernetes import client, config

CLASS_LABEL = "cape-policy/class"


def get_team_namespaces(app_class="application"):
    config.load_kube_config()
    nss = client.CoreV1Api().list_namespace(label_selector=f"{CLASS_LABEL}={app_class}")
    return sorted(n.metadata.name for n in nss.items)


if __name__ == "__main__":
    print(get_team_namespaces())
