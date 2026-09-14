import stripe

def charge(payment_method_id, amount):
    intent = stripe.PaymentIntent.create(
        amount=amount, currency="usd", payment_method=payment_method_id, confirm=True,
    )
    return intent.id  # only the token and last4 are ever stored
