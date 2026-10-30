from scapy.all import conf

from tp1.utils.config import logger


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interfaces = list(conf.ifaces.values())
    if len(interfaces) == 0:
        logger.warning("Aucune interface trouvee")
        return ""

    for i in range(len(interfaces)):
        logger.info(f"{i} - {interfaces[i].name}")

    while True:
        choix = input("Numero de l'interface : ")
        if choix.isdigit() and int(choix) < len(interfaces):
            break
        logger.warning("Mauvais numero")

    return interfaces[int(choix)].name
