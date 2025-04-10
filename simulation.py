from organization import Organization
from student import Student
from instructor import Instructor
import faker 
import sys

def simulation(student_number:int) -> None:
    print("PREPERATION PART", end="\n\n")
    o = Organization(student_number)
    i = Instructor()
    S:list[Student] = []

    fake = faker.Faker()
    for _ in range(student_number):
        S.append(Student(fake.name()))

    o.set_public_key(i.share_public_key(), 1)
    i.set_public_key(o.share_public_key())

    req = o.send_handshake_instructor()
    if req is None:
        print("Aborting...")
        return
    i.accept_handshake_organization(*req)

    for s in S:
        o.set_public_key(s.share_public_key(),0)
        s.set_public_key(o.share_public_key())

        req = o.send_handshake_student()
        if req is None:
            print("Aborting...")
            return
        s.accept_handshake_organization(*req)

    print("PREPERATION PART IS DONE!")

    print("\nSUBMISSION PART", end="\n\n")

    for s in S:
        req = s.request_ticket()
        if req is None:
            print("Aborting...")
            return
        req = o.generate_ticket(req)
        if req is None:
            print("Aborting...")
            return
        s.accept_ticket(*req)

        req = s.submit_homework()
        if req is None:
            print("Aborting...")
            return
        req = i.accept_homework(*req)
        if req is None:
            print("Aborting...")
            return
        s.receive_submit_result(req)
        s.submission_result()

    i.homeworks_results()
    
def main():
    if len(sys.argv) != 2:
        print("Student_Number is missing! Correct Usage is 'python simulation.py [student_number:int]'")
        exit(-1)
    try:
        student_number = int(sys.argv[1])
    except:
        print("Student_Number must be an integer! Aborting...")
        exit(-1)

    simulation(student_number)
        
main()

