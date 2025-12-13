import json

import gradio as gr
from cryptography.hazmat.primitives import serialization

from client_keys_generator import create_key_pair, get_public_key_pem
from constants import Actions, Permissions, Resources, public_key
from create_cert import issue_spkison

actions = [a.value.capitalize() for a in Actions]
resources = [r.value for r in Resources]


def parse_cert(
    subject_name,
    subject_id,
    permission_selected1,
    actions_selected1,
    permission_selected2,
    actions_selected2,
    permission_selected3,
    actions_selected3,
):
    if subject_name.strip() == "" or subject_id.strip() == "":
        return (
            "Subject Name and Subject ID are required",
            "Subject Name and Subject ID are required",
            "Subject Name and Subject ID are required",
        )
    valid_permissions = []

    if permission_selected1 != "" and len(actions_selected1) != 0:
        valid_permissions.append(
            Permissions(
                resource=Resources(permission_selected1),
                actions=[Actions(action.lower()) for action in actions_selected1],
            )
        )
    if permission_selected2 != "" and len(actions_selected2) != 0:
        valid_permissions.append(
            Permissions(
                resource=Resources(permission_selected2),
                actions=[Actions(action.lower()) for action in actions_selected2],
            )
        )
    if permission_selected3 != "" and len(actions_selected3) != 0:
        valid_permissions.append(
            Permissions(
                resource=Resources(permission_selected3),
                actions=[Actions(action.lower()) for action in actions_selected3],
            )
        )

    if len(valid_permissions) == 0:
        return (
            "At least one permission and correspondent action is required",
            "At least one permission and correspondent action is required",
            "At least one permission and correspondent action is required",
        )

    client_key, client_public_key = create_key_pair()

    cert = issue_spkison(
        subject_public_key_pem=get_public_key_pem(client_public_key),
        subject_name=subject_name,
        subject_id=subject_id,
        permissions=valid_permissions,
    )
    return (
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        client_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        json.dumps(cert, indent=2),
    )


with gr.Blocks() as app_ui:
    with gr.Column():
        gr.Markdown("# SPKISON CA - Certificate Generator")
        gr.Textbox(
            value=public_key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            label="SPKISON CA - Public Key (bytes - PEM Encodiing, Subject Public Key Info Format)",
        )

    subject_name = gr.Textbox(label="Subject Name")
    subject_id = gr.Textbox(label="Subject ID")

    with gr.Row(equal_height=True):
        permission_selected1 = gr.Dropdown(
            choices=resources,
            label="Permission",
            value=resources[0],
            interactive=True,
            filterable=False,
        )
        actions_selected1 = gr.CheckboxGroup(choices=actions, label="Actions Allowed")
    with gr.Row(equal_height=True):
        permission_selected2 = gr.Dropdown(
            choices=resources,
            label="Permission",
            value=None,
            interactive=True,
            filterable=False,
        )
        actions_selected2 = gr.CheckboxGroup(choices=actions, label="Actions Allowed")
    with gr.Row(equal_height=True):
        permission_selected3 = gr.Dropdown(
            choices=resources,
            label="Permission",
            value=None,
            interactive=True,
            filterable=False,
        )
        actions_selected3 = gr.CheckboxGroup(choices=actions, label="Actions Allowed")

    create_button = gr.Button("Create Certificate", variant="primary")
    create_button.click(
        fn=parse_cert,
        inputs=[
            subject_name,
            subject_id,
            permission_selected1,
            actions_selected1,
            permission_selected2,
            actions_selected2,
            permission_selected3,
            actions_selected3,
        ],
        outputs=[
            gr.Textbox(
                label="Client Private Key (bytes - PEM Encodiing, PKCS8 Format, No Encryption)",
                lines=5,
            ),
            gr.Textbox(
                label="Client Public Key (bytes - PEM Encodiing, Subject Public Key Info Format)",
                lines=5,
            ),
            gr.Textbox(label="Certificate", lines=10),
        ],
    )
