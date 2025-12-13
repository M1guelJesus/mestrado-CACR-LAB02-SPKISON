from enum import Enum

from cryptography.hazmat.primitives.asymmetric import rsa


class Actions(Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"


class Resources(Enum):
    HUMAN_RESOURCES = "api:/human_resources"
    FINANCE = "api:/finance"
    MARKETING = "api:/marketing"
    SALES = "api:/sales"
    CUSTOMER_SERVICE = "api:/customer_service"
    SUPPORT = "api:/support"
    DEVELOPMENT = "api:/development"
    DESIGN = "api:/design"
    PRODUCT = "api:/product"
    USERS = "api:/management/users"
    EXECUTIVE = "api:/executive"


class Permissions:
    def __init__(self, resource: Resources, actions: list[Actions]):
        self.resource = resource
        self.actions = actions

    def to_dict(self):
        return {
            "resource": self.resource.value,
            "actions": [action.value for action in self.actions],
        }


# Gerar chaves da autoridade
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
