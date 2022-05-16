from django.db.models import IntegerChoices


class GenderChoice(IntegerChoices):
    MALE = (0, 'Male')
    FEMALE = (1, 'Female')
