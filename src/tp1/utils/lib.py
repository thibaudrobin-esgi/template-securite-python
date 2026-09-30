from scapy.all import get_if_list

from tp1.utils.config import logger


def choose_interface() -> str:

    interfaces = get_if_list()

    print("interfaces dispo")
    for i in range(len(interfaces)):
        print(i, "->", interfaces[i])

    num = int(input("choisis une interface"))
    interface = interfaces[num]

    logger.info(f"interface choisie : {interface}")
    return interface