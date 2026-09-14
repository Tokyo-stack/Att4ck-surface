def charge(db):
    card_number = request.form["card_number"]
    cvv = request.form["cvv"]
    db.execute("INSERT INTO cards (num, cvv) VALUES (%s, %s)", (card_number, cvv))
    db.commit()
