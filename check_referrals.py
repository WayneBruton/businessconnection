"""
Check referrals for a specific business
"""

from database import get_referrals_to_business

def main():
    business_name = "Contemplation Software"
    print(f"Checking referrals for: {business_name}")
    
    referrals = get_referrals_to_business(business_name)
    print(f"Found {len(referrals)} referrals")
    
    print("\nReferral details:")
    for i, ref in enumerate(referrals):
        print(f"{i+1}. From: {ref.get('from_business')}, To: {ref.get('to_business')}")
        print(f"   Accept: {ref.get('accept')} (type: {type(ref.get('accept')).__name__})")
        print(f"   Deal Status: {ref.get('deal_accepted')} (type: {type(ref.get('deal_accepted')).__name__})")
        print(f"   Contact: {ref.get('contact_info')}")
        print(f"   Notes: {ref.get('notes')}")
        print()

if __name__ == "__main__":
    main()
