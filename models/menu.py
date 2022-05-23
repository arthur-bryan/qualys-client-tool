import controllers.controller


class Menu:
    """
    Class that represents a Menu.

    Attributes:
        controller (:obj:`Controller`): the controller responsible for the menu.
        title (str): the menu title.
        options (list): list of options of the menu.
        invalid_message (str): the message showed when the menu receive an invalid choice.
    """

    def __init__(self, controller, title: str, options: list):
        """
        Contructor method of class Menu.

        Args:
            controller: the controller responsible for the menu.
            title: the menu title.
            options: list of options of the menu.
        """
        self.controller = controller
        self.title = title
        self.options = options
        self.invalid_message = "[ - ] Invalid choice!\n"

    def open(self) -> int:
        """
        Opens the menu showing its items then receive and handle de user choice.

        Returns:
            choice: number of the user choice.
        """
        self.controller.viewer.show_menu_options(self.title, self.options)
        while True:
            try:
                choice = int(input("---> "))
            except ValueError:
                print(self.invalid_message)
                continue
            else:
                if choice not in range(1, len(self.options) + 1):
                    print(self.invalid_message)
                    continue
                return choice
