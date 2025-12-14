from gradio_ui import app_ui


def main():
    app_ui.launch(server_port=80, server_name="0.0.0.0")


if __name__ == "__main__":
    main()
