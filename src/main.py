import json
from typing import Any, TypedDict

from pishock import SerialAPI


class ShockerInfo(TypedDict):
    id: int
    type: int
    paused: bool


class HubInfo(TypedDict):
    clientId: int
    version: str
    type: int
    macAddress: str
    shockers: list[ShockerInfo]


def hub_view(info: dict[str, Any]) -> HubInfo:
    shockers: list[ShockerInfo] = []
    for shocker in info.get("shockers") or []:
        shockers.append(
            {
                "id": shocker["id"],
                "type": shocker["type"],
                "paused": shocker["paused"],
            }
        )
    return {
        "clientId": info["clientId"],
        "version": info["version"],
        "type": info["type"],
        "macAddress": info["macAddress"],
        "shockers": shockers,
    }


def main() -> None:
    api = SerialAPI(port=None)
    print(json.dumps(hub_view(api.info()), indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(exc)
        raise SystemExit(1)
